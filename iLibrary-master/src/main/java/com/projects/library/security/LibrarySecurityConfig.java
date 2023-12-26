package com.projects.library.security;

import com.projects.library.security.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class LibrarySecurityConfig {

    private final JwtAuthenticationFilter authenticationFilter;

    private LibraryUserDetailsService userDetailsService;

    //secure all the URLS except the Unscured URls
    private static final String[] SECURED_URLs = {"/books/**"};
    private static final String[] UN_SECURED_URLs = {"/books/all",
            "/books/book/{id}", "/users/**", "/authenticate/**" };



//    1. encoding the password

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public UserDetailsService userDetailsService(){
//        return new LibraryUserDetailsService();
//    }
//    @Bean
//    public AuthenticationProvider authenticationProvider(){
//        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
//        authenticationProvider.setUserDetailsService(userDetailsService());
//        authenticationProvider.setPasswordEncoder(passwordEncoder());
//        return authenticationProvider;
//    }

    //4.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        //disable the CSRF
        return http.csrf().disable()
                //we have to specify endPoints what are allowed
                .authorizeHttpRequests()
                .requestMatchers(UN_SECURED_URLs).permitAll()
                .and()
                //  we have to specify endPoints what are allowed to Admin
                .authorizeHttpRequests()
                //we need to declare List of endpoints to secure by admin
                .requestMatchers(SECURED_URLs)
                .hasAuthority("ADMIN")
                .anyRequest().authenticated()
                //enable the session management and make it stateless
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                //set the authentication provider for authentication manager
                //add the we are telling spring-security to use out filter
                .and().authenticationProvider(authenticationProvider())
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();

    }

    @Bean
    //creating a bean for authentication Manager
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {

        return authConfig.getAuthenticationManager();

    }


    public AuthenticationProvider authenticationProvider(){
        var authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }


}
