package com.projects.library.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class LibrarySecurityConfig {

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
                .and().httpBasic().and().build();

    }


}
