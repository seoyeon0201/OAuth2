package com.example.OAuth2.jwt.filter;

import com.example.OAuth2.jwt.service.JwtService;
import com.example.OAuth2.user.entity.User;
import com.example.OAuth2.user.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.parameters.P;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    //"/login"으로 들어오는 요청은 제외. Filter 작동 X
    private static final String NO_CHECK_URL = "/login";
    private static final String NO_CHECK_URL2 = "/h2-console";

    private final JwtService jwtService;
    private final UserRepository userRepository;

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // "/login"의 경우 해당 필터 호출
        if (request.getRequestURI().equals(NO_CHECK_URL) || request.getRequestURI().startsWith(NO_CHECK_URL2)) {
            filterChain.doFilter(request, response);
            return ;
        }

        log.info("1doFilterInternal", request, response);
        // refreshToken 추출
        String refreshToken = jwtService.extractRefreshToken(request)
                .filter(jwtService::isTokenValid)
                .orElse(null);

        // refreshToken이 (request header에) 존재하는 경우
        // 사용자가 accessToken이 만료되어서 refreshToken을 보낸 것이므로
        // (1) refreshToken DB와 확인 (2) 일치하는 경우 accessToken 재발급
        if (refreshToken != null) {
            checkRefreshTokenAndReIssueAccessToken(response, refreshToken);
            return;
        }

        // refreshToken이 존재하지 않는 경우
        // accessToken 검사하고 인증 처리하는 로직 처리
        // accessToken 없거나 유효하지 않은 경우, 인증 객체가 담기지 않은 상태로 다음 필터로 넘어가 403 에러 발생
        // accessToken이 유효한 경우, 인증 객체가 담긴 상태로 다음 필터로 넘어가기 때문에 인증 성공
        if (refreshToken == null) {
            checkAccessTokenAndAuthentication(request, response, filterChain);
        }
    }

    /*
    refreshToken 존재하는 경우,
    refreshToken으로 user 정보 찾기 & accessToken과 refreshToken 재발급
     */
    public void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String refreshToken) {
        log.info("2checkRefreshTokenAndReIssuAccessToken", response);
        userRepository.findByRefreshToken(refreshToken)
                .ifPresent(user -> {
                    String reIssueRefreshToken = reIssueRefreshToken(user);
                    jwtService.sendAccessAndRefreshToken(response, jwtService.createAccessToken(user.getEmail()),
                            reIssueRefreshToken);
                });
    }

    /*
    refreshToken 재발급 & DB에 refreshToken 업데이트
     */
    private String reIssueRefreshToken(User user) {
        log.info("3reIssueRefreshToken");
        String reIssuedRefreshToken = jwtService.createRefreshToken();
        user.updateRefreshToken(reIssuedRefreshToken);
        userRepository.saveAndFlush(user);
        return reIssuedRefreshToken;
    }

    /*
    accessToken 체그 & 인증 처리
     */
    public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("4checkAccessTokenAndAuthentication", request, response);
        jwtService.extractAccessToken(request)
                .filter(jwtService::isTokenValid)
                .ifPresent(accessToken -> jwtService.extractEmail(accessToken)
                        .ifPresent(email -> userRepository.findByEmail(email)
                                .ifPresent(this::saveAuthentication)));
        filterChain.doFilter(request, response);
    }

    /*
    인증 허가
     */
    public void saveAuthentication(User myUser) {
        log.info("5saveAuthentication");
        String password = myUser.getPassword();

        // 소셜로그인의 경우 password가 null. 소셜로그인은 나중에 처리
        // 아래 userDetailsUser 생성 시 password를 사용하므로 password가 null인 경우에는 오류 발생해 임의로 지정
        // 추후 String이 아닌 랜덤으로 password를 지정하는 방식으로 디벨롭 가능
        if (password == null) {
            password = "notYetPresent";
        }

        UserDetails userDetailsUser = org.springframework.security.core.userdetails.User.builder()
                .username(myUser.getEmail())
                .password(password)
                .roles(myUser.getRole().name()) //.name()을 사용해 enum 상수의 이름을 문자열로 반환
                .build();

        Authentication authentication
                = new UsernamePasswordAuthenticationToken(userDetailsUser, null,
                authoritiesMapper.mapAuthorities(userDetailsUser.getAuthorities()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
