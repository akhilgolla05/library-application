package com.projects.library.security;

import com.projects.library.user.UserRepository;
import com.projects.library.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class LibraryUserDetailsService implements UserDetailsService {

    //3. we need to load the User from Database

//    private UserService userService;

    //we can directly load from even from Repository
    @Autowired
    private UserRepository userRepository;

    //here we need to return User Details, that is why we implemented LibraryUserDetails First
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username) //here we just cant return Username, we nned to return the LibraryUserDetails( which implements IUserDetails)
                .map(LibraryUserDetails:: new) // here if User doest not found, it will throw NullPointerException
                .orElseThrow(()-> new UsernameNotFoundException("No User Found"));
    }
}
