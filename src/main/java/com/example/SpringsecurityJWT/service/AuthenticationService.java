package com.example.SpringsecurityJWT.service;

import com.example.SpringsecurityJWT.config.JwtUtil;
import com.example.SpringsecurityJWT.dto.AuthenticationResponseDto;
import com.example.SpringsecurityJWT.dto.SignInRequest;
import com.example.SpringsecurityJWT.dto.SignUpRequest;
import com.example.SpringsecurityJWT.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class AuthenticationService {
    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponseDto signUp(SignUpRequest request) {

        User user = userService.createNewUser(request);

        String jwt = jwtUtil.generateToken(user);
        return new AuthenticationResponseDto(jwt);
    }

    public AuthenticationResponseDto signIn(SignInRequest request) {


        UserDetails user = userService.loadUserByUsername(request.getUsername());

        String  jwt = jwtUtil.generateToken(user);
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user, jwt, user.getAuthorities()));
        return new AuthenticationResponseDto(jwt);
    }
}
