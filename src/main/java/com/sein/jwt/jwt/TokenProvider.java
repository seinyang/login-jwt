package com.sein.jwt.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.Arrays;
import java.util.stream.Collectors;

//3,토큰의 생성 , 유효성 검증을 담당
@Component//1.빈이 먼저 생성되고,
public class TokenProvider implements InitializingBean {
    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long tokenValidityInMilliseconds;

    private Key key;


    //2.의존성주입받은후에 secret이 값에
    public TokenProvider(
            @Value("${spring.jwt.secret}") String secret,
            @Value("${spring.jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
    }
    //3.base64 디고딩해서 key변수에 할당
    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

//    4.authentication 객체의 권한 정보를 이용해 토큰을 생성하는 createToken 메서드
//    jwt토큰을 생성해서 리턴
    public String createToken(Authentication authentication) {
        //권한
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        //토큰의 만료시간 설정,토큰 생성
        Date validity = new Date(now + this.tokenValidityInMilliseconds);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                //만료시간 대입 validity 해서 저장
                .setExpiration(validity)
                .compact();
    }

    //5.토큰 정보가 담긴 토큰을 파라미터로 담아 athentication객체를 리턴해주는 메서드
    public Authentication getAuthentication(String token) {
        //5.(2)클레임으로 만들어준다
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                //5.(1)토큰을 받아
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                //5.(3)클레임에서 권한정보를 빼내서
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
            //권한정보를 이용해서 user의 객체를 만들어준다
        User principal = new User(claims.getSubject(), "", authorities);
                                                    // user객체와 , 토큰,  권한정보를 최종적으로 athentication 객체를 통해 리턴
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    //6. 유효성 검사 할수있는 메서드(사용자가 인증됫는지 확인하는 과정)
    //6.(1)토큰을 파라미터로 담아서
    public boolean validateToken(String token) {
        try {
            //6.(2)파싱을 해보고 유효성에 문제가 있으면 false 문제가 없으면 true
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }
}
