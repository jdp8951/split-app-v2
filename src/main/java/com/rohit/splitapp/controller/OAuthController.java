package com.rohit.splitapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import com.rohit.splitapp.persistence.dto.user.AuthenticationResponse;
import com.rohit.splitapp.service.interfaces.OAuthService;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v1/oauth2")
public class OAuthController {

    @Autowired
    OAuthService oAuthService;

    @GetMapping("/callback")
    public ResponseEntity<AuthenticationResponse> handleCallback(@RequestParam("code") String code, @RequestParam("state") String state) {
        AuthenticationResponse response = oAuthService.handleCallback(code, state);
        return ResponseEntity.ok(response);
    }
}
