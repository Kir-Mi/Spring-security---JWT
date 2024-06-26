package com.example.SpringsecurityJWT.service;

import com.example.SpringsecurityJWT.dto.SignUpRequest;
import com.example.SpringsecurityJWT.model.Role;
import com.example.SpringsecurityJWT.model.User;
import com.example.SpringsecurityJWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Service
@Slf4j
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(
                String.format("Пользователь '%s' не найден", username)
        ));
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities()
        );
    }

    public User createNewUser(SignUpRequest signUpRequest) {
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        user.setRoles(List.of(Role.ROLE_USER));
        log.info("User saved");
        return userRepository.save(user);
    }

    public void getAdminRole() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Not found"));
        user.setRoles(List.of(Role.ROLE_ADMIN));
        log.info(username + " is an admin now");
        userRepository.save(user);
    }
}
