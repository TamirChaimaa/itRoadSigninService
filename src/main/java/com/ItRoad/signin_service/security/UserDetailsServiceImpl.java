package com.ItRoad.signin_service.security;

import com.ItRoad.signin_service.models.User;
import com.ItRoad.signin_service.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Collections;

/**
 * Custom implementation of Spring Security's UserDetailsService interface.
 * Used to retrieve user information from the database during authentication.
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository; // Injects the UserRepository to access user data

    /**
     * Loads the user by their username.
     *
     * @param username the username of the user
     * @return UserDetails object with username, password, and roles
     * @throws UsernameNotFoundException if the user is not found
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername()) // Set the username
                .password(user.getPassword()) // Set the hashed password
                .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole()))) // Set user role
                .build();
    }
}
