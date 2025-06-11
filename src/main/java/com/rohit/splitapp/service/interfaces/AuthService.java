package com.rohit.splitapp.service.interfaces;

import com.rohit.splitapp.persistence.dto.user.AuthenticationResponse;
import com.rohit.splitapp.persistence.dto.user.LoginRequest;
import com.rohit.splitapp.persistence.dto.user.RefreshTokenRequest;

public interface AuthService {
    public AuthenticationResponse authenticateUser(LoginRequest loginRequest);
    public AuthenticationResponse issueNewToken(RefreshTokenRequest refreshTokenRequest);
}
