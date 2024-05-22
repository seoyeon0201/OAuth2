package com.example.OAuth2.user.repository;

import com.example.OAuth2.user.SocialType;
import com.example.OAuth2.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    Optional<User> findByNickname(String nickname);
    Optional<User> findByRefreshToken(String refreshToken);

    /*
        OAuth2 로그인 구현 시 추가 정보를 위해 SocialType과 socialId로 회원 찾는 메소드
        추가 정보를 입력받아 회원 가입을 진행할 때 social type, socialID로 해당 회원을 찾기 위한 메소드
     */
    Optional<User> findBySocialTypeAndSocialId(SocialType socialType, String socialId);
}
