package com.rohit.splitapp.service.interfaces;

import java.util.UUID;

import com.rohit.splitapp.persistence.dto.user.RegisterUserRequest;
import com.rohit.splitapp.persistence.dto.user.UserDTO;

public interface UserService {
    String saveUser(RegisterUserRequest registerUserRequest);

    UserDTO findUser();

    String deleteUser();

    String updateUser(RegisterUserRequest registerUserRequest);

}
