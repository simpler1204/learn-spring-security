package com.in28minutes.learnspringsecurity.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final JdbcUserDetailsManager userDetailsManager;
    private final PasswordEncoder passwordEncoder;

    public UserService(JdbcUserDetailsManager userDetailsManager, PasswordEncoder passwordEncoder) {
        this.userDetailsManager = userDetailsManager;
        this.passwordEncoder = passwordEncoder;
    }

    public void registerUser(String username, String rawPassword) {
        if (!userDetailsManager.userExists(username)) {
            UserDetails user = org.springframework.security.core.userdetails.User
                    .withUsername(username)
                    .password(passwordEncoder.encode(rawPassword))
                    .roles("ADMIN")
                    .build();
            userDetailsManager.createUser(user);
        }
    }
}
