package com.rohit.splitapp.service.implementations;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.rohit.splitapp.configuration.security.LoggedInUser;
import com.rohit.splitapp.persistence.entities.User;
import com.rohit.splitapp.repository.UserRepository;

@Service
public class AuthorizationService {

    @Autowired
    LoggedInUser loggedInUser;

    @Autowired
    UserRepository userRepository;


    public User getAuthorizedUser() {
        return userRepository.findByEmail(loggedInUser.getUserEmail()).orElseThrow(() -> new RuntimeException("User not found"));
    }
}
