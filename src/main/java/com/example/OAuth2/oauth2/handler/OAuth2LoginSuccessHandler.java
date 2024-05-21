package com.example.OAuth2.oauth2.handler;

import com.example.OAuth2.jwt.service.JwtService;
import com.example.OAuth2.oauth2.CustomOAuth2User;
import com.example.OAuth2.user.Role;
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

            //User의 Role이 GUEST인 경우 처음 요청한 회원이므로 회원 가입 페이지로 리다이렉트
            if (oAuth2User.getRole() == Role.GUEST) {
                String accessToken = jwtService.createAccessToken(oAuth2User.getEmail());
                response.addHeader(jwtService.getAccessHeader(), "BEARER " + accessToken);
                //프론트의 회원 가입 추가 정보 입력 폼으로 리다이렉트
                response.sendRedirect("oauth2/sign-up");

                jwtService.sendAccessAndRefreshToken(response, accessToken, null);
            }
            else {
                //로그인 성공한 경우 access, refresh token 생성
                loginSuccess(response, oAuth2User);
            }
        } catch (Exception e) {
            throw e;
        }
    }

    private void loginSuccess(HttpServletResponse response, CustomOAuth2User oAuth2User) throws IOException {
        String accessToken = jwtService.createAccessToken(oAuth2User.getEmail());
        String refreshToken = jwtService.createRefreshToken();
        response.addHeader(jwtService.getAccessHeader(), "BEARER " + accessToken);
        response.addHeader(jwtService.getRefreshHeader(), "BEARER " + refreshToken);

        jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);
        jwtService.updateRefreshToken(oAuth2User.getEmail(), refreshToken);
    }
}
