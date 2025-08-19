package com.in28minutes.learnspringsecurity.dto;

import lombok.Data;

import java.util.List;

@Data
public class UserRequestDTO {
    private String username;
    private String password;
}

