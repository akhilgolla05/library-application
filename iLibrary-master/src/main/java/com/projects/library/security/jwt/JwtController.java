package com.projects.library.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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

    private final AuthenticationManager authenticationManager;

    //when the user is authenticated, this controller genertes the JWT token
    @PostMapping
    public String getTokenForAuthenticatedUser(
            @RequestBody JwtAuthenticationRequest authRequest){

//        check entered user is valid or not ?
        //for that we are using Authentication class to authenticate user
        //before token gets created, the user must authenticated.
      Authentication authentication = authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(
                      authRequest.getUserName(), authRequest.getPassword()));

      if(authentication.isAuthenticated()){

          //when user enters the username and password, spring security will
          //take username , and generated a token for a user
          return jwtService.getGeneratedToken(authRequest.getUserName());
      }
      else{
          throw new UsernameNotFoundException("Invalid User Credentials");
      }



    }
}
