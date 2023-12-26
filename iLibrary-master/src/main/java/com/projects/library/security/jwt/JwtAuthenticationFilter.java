package com.projects.library.security.jwt;

import com.projects.library.security.LibraryUserDetails;
import com.projects.library.security.LibraryUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/*

this class is to filter the JWT token
i.e, to get username, expiration time from the token, so spring security knows
about the user.
 */

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private LibraryUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = null;
        String userName = null;
        //to get the header(Autherization tab-postman) request to extract the token
        String authHeader = request.getHeader("Authorization");
        //if header contains token
        if(authHeader != null && authHeader.startsWith("Bearer ")){
            //get original token
            token = authHeader.substring(7);
            userName = jwtService.extractUsernameFromToken(token);

        }
        //if userName present in the token and that user is not authenticated (user should be a valid user)
        if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null){

            //get user details from the databsse using the username which we extracted from the token
          UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

          //validating token against the userdetails
            //credentials will be null, unknown user is trying
            var authToken = new UsernamePasswordAuthenticationToken(token, null,userDetails.getAuthorities());

            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            //setting the authenticated token for the user
            SecurityContextHolder.getContext().setAuthentication(authToken);

        }

        filterChain.doFilter(request, response);
    }
}
