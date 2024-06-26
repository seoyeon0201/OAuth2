package com.example.OAuth2.oauth2.service;

import com.example.OAuth2.oauth2.CustomOAuth2User;
import com.example.OAuth2.oauth2.OAuthAttributes;
import com.example.OAuth2.s3.service.FileUploadService;
import com.example.OAuth2.user.SocialType;
import com.example.OAuth2.user.entity.User;
import com.example.OAuth2.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final UserRepository userRepository;
    private final FileUploadService fileUploadService;

    private static final String NAVER = "naver";
    private static final String KAKAO = "kakao";

    //Authorization Server에서 token 발급 받아 Resource Server에서 User 정보 가져온 후 loadUser() 사용
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("CustomOAuth2UserService.loadUser() 실행 - OAuth2 로그인 요청 진입");

        /*
        DefaultOAuth2UserService 객체 생성해 loadUser(userRequest)를 통해 DefaultOAuth2User 객체 생성 후 반환
        DefaultOAuth2UserService의 loadUser()는 소셜 로그인 API의 사용자 정보 제공 URI로 요청을 보내 사용자 정보 얻은 후 DefaultOAuth2User 객체 생성 후 반환
        결과적으로 OAuth2User는 OAuth 서비스에서 가져온 유저 정보를 담고 있는 유저
         */
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        /*
        userRequest에서 registrationId 추출 후 registrationId로 SocialType 저장
        예를 들어 http://localhost:8080/oauth2/authorization/kakao에서 kakao가 registrationId
        userNameAttributeName은 이후에 nameAttributeKey로 설정
         */
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        SocialType socialType = getSocialType(registrationId);
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName(); //oauth2 로그인 시 PK 키 값
        Map<String, Object> attributes = oAuth2User.getAttributes();    //소셜 로그인에서 API가 제공하는 userInfo의 JSON 값(유저정보데이터)

        /*
        socialType에 따라 유저 정보를 통해 OAuthAttribute 객체 생성
         */
        OAuthAttributes extractAttributes = OAuthAttributes.of(socialType, userNameAttributeName, attributes);

        /*
        getUser() 메소드로 User 객체 생성 후 반환
         */
        User createdUser = getUser(extractAttributes, socialType);

        /*
        소셜로그인으로 받아온 image s3에 저장
         */
        try {
            fileUploadService.uploadS3Social(createdUser.getEmail(), createdUser.getImageUrl());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        /*
        DefaultOAuth2User를 구현한 CustomOAuth2User 객체 생성해 반환
         */

        return new CustomOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(createdUser.getRole().getKey())),
                attributes,
                extractAttributes.getNameAttributeKey(),
                createdUser.getEmail(),
                createdUser.getRole()
        );
    }

    private SocialType getSocialType(String registrationId) {
        if (NAVER.equals(registrationId)) {
            return SocialType.NAVER;
        }
        if (KAKAO.equals(registrationId)) {
            return SocialType.KAKAO;
        }
        return SocialType.GOOGLE;
    }

    /*
    SocialType과 attributes에 들어있는 소셜 로그인의 식별값 id를 통해 회원 찾아 반환하는 메소드
    만약 찾은 회원이 있다면 그대로 반환, 없다면 saveUser()를 호출해 회원 저장
     */
    private User getUser(OAuthAttributes attributes, SocialType socialType) {
        User findUser = userRepository.findBySocialTypeAndSocialId(socialType, attributes.getOauth2UserInfo().getId()).orElse(null);

        if (findUser == null) {
            return saveUser(attributes, socialType);
        }
        return findUser;
    }

    /*
    OAuthAttributes의 toEntity() 메소드를 통해 빌더로 User 객체 생성 후 반환
    생성된 User 객체 DB에 저장: socialType, socialId, email, role 값만 있는 상태
     */
    private User saveUser(OAuthAttributes attributes, SocialType socialType) {

        User createdUser = attributes.toEntity(socialType, attributes.getOauth2UserInfo());
        return userRepository.save(createdUser);
    }
}
