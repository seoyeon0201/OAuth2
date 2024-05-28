package com.example.OAuth2.oauth2.handler;

import com.example.OAuth2.jwt.service.JwtService;
import com.example.OAuth2.oauth2.CustomOAuth2User;
import com.example.OAuth2.s3.service.FileUploadService;
import com.example.OAuth2.user.Role;
import com.example.OAuth2.user.entity.User;
import com.example.OAuth2.user.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 Login 성공!");

        try {
            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

            Map<String, Object> attributes = oAuth2User.getAttributes();

            //User의 Role이 GUEST인 경우 처음 요청한 회원이므로 회원 가입 페이지로 리다이렉트
            if (oAuth2User.getRole() == Role.GUEST) {
                //accessToken 생성
                String accessToken = jwtService.createAccessToken(oAuth2User.getEmail());
                //response.addHeader(jwtService.getAccessHeader(), "BEARER " + accessToken); //해도 덮어씌워짐. sendAccessAndRefreshToken() 메소드 동작 시 header 설정

                //log.info("Role=GUEST");

                //프론트의 회원 가입 추가 정보 입력 폼으로 리다이렉트
                //response.sendRedirect("oauth2/sign-up");

                //해당 로직은 Role을 강제로 User로 바꾸는 것이므로 회원 가입 추가 입력 폼이 있는 경우 해당 로직 필요없음
                User findUser = userRepository.findByEmail(oAuth2User.getEmail())
                                .orElseThrow(() -> new IllegalArgumentException("이메일에 해당하는 유저가 없습니다."));
                findUser.authorizeUser();
                userRepository.saveAndFlush(findUser);  //handler에서 직접 DB에 접근하는 것은 권장되지 않음

                /*
                임시 토큰. response header에 전달
                회원 가입 폼 기입 완료 전까지 사용하다가 폼 기입 완료하면 최종 token 생성
                 */
                String tempToken = jwtService.createRefreshToken();  //원래는 회원 가입 폼 기입 후 설정되어야 함
                response.setHeader("TempToken", tempToken);
                log.info("temptoke 발급");
            }
            else {
                //로그인 성공한 경우 최종 token인 access, refresh token 생성
                //log.info("Role=USER");
                /*
                token 발급해 처리
                1. accessToken과 refreshToken header에 넣어 전송
                2. refreshToken DB에 저장
                 */
                loginSuccess(response, oAuth2User);
            }
        } catch (Exception e) {
            throw e;
        }
    }

    /*
    무조건 token 생성하지 않고 JWT 인증 필터처럼 refreshToken 유무, 만료 기간에 따라 다르게 처리
     */
    private void loginSuccess(HttpServletResponse response, CustomOAuth2User oAuth2User) throws IOException {
        String accessToken = jwtService.createAccessToken(oAuth2User.getEmail());
        String refreshToken = jwtService.createRefreshToken();
        //jwtService.sendAccessAndRefreshToken()에서 header 세팅하므로 의미없음
        //response.addHeader(jwtService.getAccessHeader(), "BEARER " + accessToken);
        //response.addHeader(jwtService.getRefreshHeader(), "BEARER " + refreshToken);

        jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);
        jwtService.updateRefreshToken(oAuth2User.getEmail(), refreshToken);
    }
}
