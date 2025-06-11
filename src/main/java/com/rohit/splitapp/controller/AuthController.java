package com.rohit.splitapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.rohit.splitapp.persistence.dto.user.AuthenticationResponse;
import com.rohit.splitapp.persistence.dto.user.LoginRequest;
import com.rohit.splitapp.persistence.dto.user.RefreshTokenRequest;
import com.rohit.splitapp.service.interfaces.AuthService;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> loginUser(@RequestBody LoginRequest loginRequest) {
        AuthenticationResponse response = authService.authenticateUser(loginRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh_token")
    public ResponseEntity<AuthenticationResponse> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        AuthenticationResponse response = authService.issueNewToken(refreshTokenRequest);
        return ResponseEntity.ok(response);
    }
}