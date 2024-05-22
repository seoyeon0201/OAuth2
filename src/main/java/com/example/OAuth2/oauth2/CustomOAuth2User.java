package com.example.OAuth2.oauth2;

import com.example.OAuth2.user.Role;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Collection;
import java.util.Map;

//OAuth2User 객체 커스텀
@Getter
public class CustomOAuth2User extends DefaultOAuth2User {
    private String email;
    private Role role;

    /*
    생성자
    authorities: the authorities granted to the user
    attributes: the attributes about the user
    nameAttributeKey: the key used to access the user's &quot;name&quot;
     */
    public CustomOAuth2User(Collection<? extends GrantedAuthority> authorities,
                            Map<String,Object> attributes, String nameAttributeKey,
                            String email, Role role) {
        super(authorities, attributes, nameAttributeKey);   //부모 객체에 존재
        this.email = email;
        this.role = role;
    }

}
