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




/*

This code appears to be a filter that intercepts incoming HTTP requests to check for JWT-based authentication in a Spring Security context. Let's go through it step by step:

protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {: This method overrides the doFilterInternal method of a javax.servlet.Filter class, indicating that it intercepts incoming HTTP requests.

String token = null; String userName = null;: Initializes variables token and userName to null.

String authHeader = request.getHeader("Authorization");: 
Retrieves the "Authorization" header from the incoming HTTP request.

if(authHeader != null && authHeader.startsWith("Bearer ")) {:
Checks if the Authorization header is not null and starts with "Bearer ", indicating it's a Bearer token (JWT).

token = authHeader.substring(7);:
Extracts the token string by removing the "Bearer " prefix from the Authorization header.

userName = jwtService.extractUsernameFromToken(token);: 
Uses a jwtService (presumably a service class) to extract the username from the JWT token.

if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {: 
Checks if the username is not null and if there's no existing authentication in the SecurityContextHolder.

UserDetails userDetails = userDetailsService.loadUserByUsername(userName);:
Loads user details (presumably from a userDetailsService) using the extracted username.

var authToken = new UsernamePasswordAuthenticationToken(token, null, userDetails.getAuthorities());:
Creates an authentication token (authToken) of type UsernamePasswordAuthenticationToken using the token string, null credentials, and the authorities loaded from the user details.

authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));:
Sets additional details for the authentication token, such as the source of authentication details from the incoming request.

SecurityContextHolder.getContext().setAuthentication(authToken);:
Sets the authentication token in the SecurityContextHolder.

filterChain.doFilter(request, response);:
Passes the request and response objects along the filter chain for further processing.

Overall, this filter intercepts requests, checks for a Bearer token in the Authorization header, 
extracts the username from the token, loads user details, creates an authentication token,
and sets it in the SecurityContextHolder for further processing of the request within the security context.




*/
