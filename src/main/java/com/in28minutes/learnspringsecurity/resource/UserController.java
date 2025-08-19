package com.in28minutes.learnspringsecurity.resource;

import com.in28minutes.learnspringsecurity.dto.UserRequestDTO;
import com.in28minutes.learnspringsecurity.service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;

@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public void registerUser(@RequestBody UserRequestDTO dto) {

        userService.registerUser(dto.getUsername(), dto.getPassword());
    }
}
