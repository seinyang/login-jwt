package com.sein.jwt.service;

import com.sein.jwt.repository.UserRepository;
import jakarta.transaction.Transactional;
import com.sein.jwt.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;


import java.util.List;
import java.util.stream.Collectors;


@Component("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
        @Override
        @Transactional
        //여기가 컨트롤러에서 넘어와서 실행됨
        public UserDetails loadUserByUsername(final String username) {

            //로그인시에 DB에서 유저정보와 권한 정보를 가져오고
            return userRepository.findOneWithAuthoritiesByUsername(username)
                    .map(user -> createUser(username, user))
                    .orElseThrow(() -> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));
        }

        private org.springframework.security.core.userdetails.User createUser(String username, User user) {

            if (!user.isActivated()) {
                throw new RuntimeException(username + " -> 활성화되어 있지 않습니다.");
            }
            List<GrantedAuthority> grantedAuthorities = user.getAuthorities().stream()
                    //해당 정보를 기반으로 USER객체를 생성해서 리턴
                    .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
                    .collect(Collectors.toList());

            return new org.springframework.security.core.userdetails.User(user.getUsername(),
                    user.getPassword(),
                    grantedAuthorities);
        }
}
