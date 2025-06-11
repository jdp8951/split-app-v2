package com.rohit.splitapp.controller;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.rohit.splitapp.persistence.dto.user.RegisterUserRequest;
import com.rohit.splitapp.persistence.dto.user.UserDTO;
import com.rohit.splitapp.service.interfaces.UserService;


@RestController
@RequestMapping("/api/v1/user")
public class UserController {

    @Autowired
    private UserService userService;

  
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegisterUserRequest registerUserRequest) {
        String response = userService.saveUser(registerUserRequest);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

   
    @GetMapping("")
    public ResponseEntity<UserDTO> getUser() {
        UserDTO response = userService.findUser();
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }


    @PutMapping("update/{userId}")
    public ResponseEntity<String> updateUser(@Valid @RequestBody RegisterUserRequest updateUserRequest) {
        String response = userService.updateUser(updateUserRequest);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @DeleteMapping("delete")
    public ResponseEntity<String> deleteUser() {
        String response = userService.deleteUser();
        return ResponseEntity.ok(response);
    }

}
