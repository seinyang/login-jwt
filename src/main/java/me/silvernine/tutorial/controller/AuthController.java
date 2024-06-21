package me.silvernine.tutorial.controller;


import me.silvernine.tutorial.dto.LoginDto;
import me.silvernine.tutorial.dto.TokenDto;
import me.silvernine.tutorial.jwt.JwtFilter;
import me.silvernine.tutorial.jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }
    //POST요청을 받음
    @PostMapping("/authenticate")
    //loginDto로 파라미터로 받고!
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        UsernamePasswordAuthenticationToken authenticationToken =
                //getUsername,getPassword 을받고 authenticationToken 객체 생성
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        //authenticate 가 실행될때 서비스의 로드 유저바이 유저네임이 실행됨
        //그결과값이 담긴 객체를 생성받아서
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        //SecurityContextHolder에 저장하고
        SecurityContextHolder.getContext().setAuthentication(authentication);
        //그인증정보를 기준으로해서 생성한 createToken 으로 만든 걸로 jwt생성
        String jwt = tokenProvider.createToken(authentication);

        HttpHeaders httpHeaders = new HttpHeaders();
        //생성된 jwt를 헤더에도 넣어주고
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
        //responsebody에도 리턴해줌
        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}
