package com.projects.library.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

//1. here we are creating an end-point to authenticate user

@RestController
//we have to allow this endpoint for free, bexz when user enters the username
//and password, then req sends to the this api, this is responsible
//to generate the token
@RequestMapping("/authenticate")
@RequiredArgsConstructor
public class JwtController {

    private final JwtService jwtService;

    //when the user is authenticated, this controller genertes the JWT token
    @PostMapping
    public String getTokenForAuthenticatedUser(
            @RequestBody JwtAuthenticationRequest authRequest){

        //when user enters the username and password, spring security will
        //take username , and generated a token for a user

        return jwtService.getGeneratedToken(authRequest.getUserName());

    }
}
