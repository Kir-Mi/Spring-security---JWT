package com.example.SpringsecurityJWT.controller;

import com.example.SpringsecurityJWT.dto.AuthenticationResponseDto;
import com.example.SpringsecurityJWT.dto.SignInRequest;
import com.example.SpringsecurityJWT.dto.SignUpRequest;
import com.example.SpringsecurityJWT.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authService;

    @PostMapping("/auth")
    public AuthenticationResponseDto createAuthToken(@RequestBody SignInRequest signInRequest) {
        return authService.signIn(signInRequest);
    }

    @PostMapping("/registration")
    public AuthenticationResponseDto createNewUser(@RequestBody SignUpRequest registrationUserDto) {
        return authService.signUp(registrationUserDto);
    }
}

