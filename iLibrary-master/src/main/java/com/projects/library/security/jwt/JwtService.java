package com.projects.library.security.jwt;

import com.projects.library.user.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/*
3.

Access tokens are JSON web tokens (JWT). JWTs contain the following pieces:
•Header - Provides information about how to validate the token including
information about the type of token and its signing method.

•Payload - Contains all of the important data about the user or
application that's attempting to call the service.

•Signature - Is the raw material used to validate the token.
Each piece is separated by a period (.) and separately Base 64 encoded.


 */

@Service
@NoArgsConstructor
@AllArgsConstructor

public class JwtService {


    @Value("${spring.jwt.secret}")
    private String JWT_SECRET;

    @Value("${spring.jwt.jwtExpirationTime}")
    private int JWT_EXPIRATION_TIME;



    public String getGeneratedToken(String userName) {
//here Object is Token
        Map<String, Object> claims = new HashMap<>();
        return generateTokenForUser(claims, userName);
    }


    /*
    jwt.io
    -> jwt token has 3 components (Header-red, Payload-violet, Signatute-blue)
    ->Header defines the algorithm we are using ie., HS256
    ->Payload consists of sub, username and issued at. ie., information of user
    ->Signature contains a secret key, secret key used to encode the token for the user.

    => All components are called claims
    JWT claims are located in the payload section and
     provide essential information regarding the user and
      the context of the token.
       JWT claims can be divided into two categories:
       registered claims and custom claims.





     */

    private String generateTokenForUser(Map<String, Object> claims, String userName) {

        return Jwts.builder().setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_EXPIRATION_TIME))
                //we are using here hashing Signature algorithm
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    //method is used to generate the secret key
    private Key getSignKey() {
        //here we are decoding the secret key
        byte[] keyBytes = Decoders.BASE64.decode(JWT_SECRET);

        return Keys.hmacShaKeyFor(keyBytes);
    }
}
