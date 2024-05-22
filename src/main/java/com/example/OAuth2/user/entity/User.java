package com.example.OAuth2.user.entity;

import com.example.OAuth2.user.Role;
import com.example.OAuth2.user.SocialType;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.crypto.password.PasswordEncoder;

@Getter
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@AllArgsConstructor
@Entity
@Builder
@Table(name="USERS")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    private String email;
    private String password;
    private String name;
    private String imageUrl;    //프로필 URL
    private int age;
    private String city;
    private String nickname;
    @Enumerated(EnumType.STRING)
    private Role role;

    @Enumerated(EnumType.STRING)
    private SocialType socialType;  //KAKAO, NAVER, GOOGLE
    private String socialId;    //로그인한 소셜 타입의 식별자 값
    private String refreshToken;

    //유저 권한 설정
    public void authorizeUser() {
        this.role = Role.USER;
    }

    //비밀번호 암호화 메소드
    public void passwordEncode(PasswordEncoder passwordEncoder) {
        this.password = passwordEncoder.encode(this.password);
    }

    public void updateRefreshToken(String updateRefreshToken) {
        this.refreshToken = updateRefreshToken;
    }
}
