package com.example.OAuth2.oauth2;

import com.example.OAuth2.oauth2.userinfo.GoogleOAuth2UserInfo;
import com.example.OAuth2.oauth2.userinfo.OAuth2UserInfo;
import com.example.OAuth2.user.Role;
import com.example.OAuth2.user.SocialType;
import com.example.OAuth2.user.entity.User;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;
import java.util.UUID;

@Getter
public class OAuthAttributes {
    private String nameAttributeKey;    //OAuth2 로그인 진행 시 키가 되는 필드 값. PK와 같은 의미
    private OAuth2UserInfo oauth2UserInfo;  //소셜 타입 별 로그인 유저 정보(닉네임, 이메일, 프로필 사진 등)

    @Builder
    private OAuthAttributes(String nameAttributeKey, OAuth2UserInfo oauth2UserInfo) {
        this.nameAttributeKey = nameAttributeKey;
        this.oauth2UserInfo = oauth2UserInfo;
    }

    /*
    SocialType에 맞는 메소드 호출해 OAuthAttributes 객체 반환
     */
    public static OAuthAttributes of(SocialType socialType, String userNameAttributeName, Map<String, Object> attributes) {
        //카카오, 네이버 추가하면 if 있어야 하지만, if가 있으면 return 값이 nullable해 일단 주석
        //추후 다른 소셜 타입 추가되면 주석 제거

//        if (socialType == SocialType.GOOGLE) {
//            return ofGoogle(userNameAttributeName, attributes);
//        }

        return ofGoogle(userNameAttributeName, attributes);
    }

    //Google
    public static OAuthAttributes ofGoogle(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oauth2UserInfo(new GoogleOAuth2UserInfo(attributes))
                .build();
    }

    /*
    of메소드로 OAuthAttribute 객체 생성되어 유저 정보가 담긴 OAuth2UserInfo가 소셜 타입별로 주입된 상태

     */
    public User toEntity(SocialType socialType, OAuth2UserInfo oAuth2UserInfo) {
        return User.builder()
                .socialType(socialType)
                .socialId(oauth2UserInfo.getId())
                .email(UUID.randomUUID() + "@socialUser.com")
                .nickname(oAuth2UserInfo.getImageUrl())
                .role(Role.GUEST)
                .build();
    }



}