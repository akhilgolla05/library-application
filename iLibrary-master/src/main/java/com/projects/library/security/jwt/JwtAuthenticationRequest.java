package com.projects.library.security.jwt;

import lombok.Data;

//2
@Data
public class JwtAuthenticationRequest {

    private String userName;
    private String password;

}
