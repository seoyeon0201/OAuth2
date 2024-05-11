package com.example.OAuth2.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
    //Role이라는 enum 선언. enum의 상수로 GUEST와 USER를 가지고, 각각 ROLE_GUEST와 ROLE_USER를 가짐
    //OAuth2 로그인 시 첫 로그인을 구분하기 위해. 첫 방문 시 ROLE_GUEST, 이후로는 ROLE_USER
    //자체 로그인의 경우, 회원 가입 시 입력받아야 하는 모든 정보가 이미 저장되어 있으므로 첫 로그인임에도 USER 상태
    //key 필드를 추가해 "ROLE_" 붙인 이유는 Spring Security에서는 Role 코드에 항상 "ROLE_" 접두사가 붙어야 하기 때문
    GUEST("ROLE_GUEST"), USER("ROLE_USER");

    //enum 상수에 대한 key 값. enum 상수를 구분하는데 사용하며 enum 상수마다 고유한 key 값 가짐
    private final String key;

}
