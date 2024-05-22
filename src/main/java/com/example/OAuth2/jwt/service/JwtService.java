package com.example.OAuth2.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.OAuth2.YamlPropertySourceFactory;
import com.example.OAuth2.user.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import javax.swing.text.html.Option;
import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Getter
@Slf4j
@PropertySource(value="classpath:application-jwt.yml",factory= YamlPropertySourceFactory.class)
public class JwtService {

    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationPeriod;

    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirationPeriod;

    @Value("${jwt.access.header}")
    private String accessHeader;

    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    /*
    JWT의 Subject와 Claim으로 email 사용 -> claim name을 "email"로 설정
    JWT의 Header에 들어오는 값: "Authorization(Key) = Bearer {토큰} (Value)" 형식
     */
    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String EMAIL_CLAIM = "email";
    private static final String BEARER = "Bearer";

    private final UserRepository userRepository;


    /*
    AccessToken 생성
     */
    public String createAccessToken(String email) {

        Date now = new Date();
        return JWT.create()
                .withSubject(ACCESS_TOKEN_SUBJECT)  //jwt 이름
                .withExpiresAt(new Date(now.getTime() + accessTokenExpirationPeriod))//jwt 만료시간. 설정하지 않는 경우 무한 지속
                .withClaim(EMAIL_CLAIM, email) //jwt의 payload부분에서 private 설정. private 이름과 그 내용
                .sign(Algorithm.HMAC512(secretKey));    //어떤 해싱 알고리즘으로 해시하고 어떤 시크릿키 사용하는지 결정
    }

    /*
    RefreshToken 생성
     */
    public String createRefreshToken() {

        Date now = new Date();
        return JWT.create()
                .withSubject(REFRESH_TOKEN_SUBJECT)
                .withExpiresAt(new Date(now.getTime() + refreshTokenExpirationPeriod))
                .sign(Algorithm.HMAC512(secretKey));
    }

    /*
    AccessToken Header에 실어 보내기
     */
    public void sendAccessToken(HttpServletResponse response, String accessToken) {

        response.setStatus(HttpServletResponse.SC_OK);

        response.setHeader(accessHeader, accessToken);
        log.info("재발급된 Access Token: {}", accessToken);
    }

    /*
    AccessToken + RefreshToken Header에 실어 보내기
     */
    public void sendAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken) {

        response.setStatus(HttpServletResponse.SC_OK);

        setAccessTokenHeader(response, accessToken);
        setRefreshTokenHeader(response, refreshToken);
        log.info("Access Token, Refresh Token 헤더 설정 완료");
    }

    /*
    헤더에서 RefreshToken 추출
    토큰 형식: Bearer XXX에서 Bearer를 제외하고 순수 토큰만 가져오기 위해
    헤더를 가져온 후 "Bearer"를 삭제(""로 replace)
     */
    public Optional<String> extractRefreshToken(HttpServletRequest request) {

        return Optional.ofNullable(request.getHeader(refreshHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    /*
    헤더에서 AccessToken 추출
    토큰 형식: Bearer XXX에서 Bearer를 제외하고 순수 토큰만 가져오기 위해
    헤더를 가져온 후 "Bearer"를 삭제(""로 replace)
     */
    public Optional<String> extractAccessToken(HttpServletRequest request) {

        return Optional.ofNullable(request.getHeader(accessHeader))
                .filter(accessToken -> accessToken.startsWith(BEARER))
                .map(accessToken -> accessToken.replace(BEARER, ""));
    }

    /*
    AccessToken에서 email 추출
    추출 전에 JWT.require()로 검증기 생성
    verify로 AccessToken 검증
    유효한 경우 getClaim()으로 이메일 추출
    유효하지 않은 경우 빈 Optional 객체 반환
     */
    public Optional<String> extractEmail(String accessToken) {
        try {
            return Optional.ofNullable(JWT.require(Algorithm.HMAC512(secretKey))
                            .build()
                            .verify(accessToken)
                            .getClaim(EMAIL_CLAIM)
                            .asString());
        } catch (Exception e) {
            log.error("액세스 토큰이 유효하지 않습니다.");
            return Optional.empty();
        }
    }

    /*
    AccessToken 헤더 설정
     */
    public void setAccessTokenHeader(HttpServletResponse response, String accessToken) {
        response.setHeader(accessHeader, "BEARER " + accessToken);
    }

    /*
    RefreshToken 헤더 설정
     */
    public void setRefreshTokenHeader(HttpServletResponse response, String refreshToken) {
        response.setHeader(refreshHeader,"BEARER " + refreshToken);
    }

    /*
    RefreshToken DB 저장(업데이트)
     */
    public void updateRefreshToken(String email, String refreshToken) {
        userRepository.findByEmail(email)
                .ifPresentOrElse(
                        //DB에 email이 일치하는 회원이 있는 경우
                        user -> {
                            user.updateRefreshToken(refreshToken);
                            userRepository.save(user);
                        },
                        //DB에 email이 일치하는 회원이 없는 경우
                        () -> new Exception("일치하는 회원이 없습니다.")
                );
    }

    /*
    token valid 검사
     */
    public boolean isTokenValid(String token) {
        try {
            JWT.require(Algorithm.HMAC512(secretKey)).build().verify(token);
            return true;
        } catch (Exception e) {
            log.error("유효하지 않은 토큰입니다. {}", e.getMessage());
            return false;
        }
    }


}
