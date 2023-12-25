package com.projects.library.security;

import com.projects.library.user.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

//2. implementing spring-sec for user details

@Data
public class LibraryUserDetails implements UserDetails {

    //     we have to return the password of the user and Username, actullay to find a way
    // to login to the application
    private String userName;
    private String password;


    //here we are expected to return the collection of granted authoroties( like - user, admin, etc..).

    private List<GrantedAuthority> authorities;


    //we need to return thr user, so he can login with username, password and authorities

    public LibraryUserDetails(User user) {
        userName = user.getEmail();
        password = user.getPassword();
        authorities = Arrays.stream(user.getRoles()
                .split(",")).map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }


    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
