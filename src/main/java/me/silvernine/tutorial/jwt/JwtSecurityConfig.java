package me.silvernine.tutorial.jwt;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//5. 3,4번에 만든(필터,프로바이더) 클래스를 SecurityConfig에 사용할 클래스
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private TokenProvider tokenProvider;
    //1.토큰 프로바이더를 주입받고
    public JwtSecurityConfig(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void configure(HttpSecurity http) {
        //2.jwt필터를 통해
        JwtFilter customFilter = new JwtFilter(tokenProvider);
        //3.시큐리티 로직에 필터를 등록해줌(add)
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}