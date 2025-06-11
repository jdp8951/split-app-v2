package com.rohit.splitapp.service.interfaces;

import com.rohit.splitapp.persistence.dto.user.AuthenticationResponse;

public interface OAuthService {
    public AuthenticationResponse handleCallback(String code, String state);
}
