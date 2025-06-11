package com.rohit.splitapp.controller;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.rohit.splitapp.configuration.security.LoggedInUser;
import com.rohit.splitapp.persistence.dto.group.GroupDTO;
import com.rohit.splitapp.persistence.dto.group.GroupListDTO;
import com.rohit.splitapp.persistence.dto.group.GroupUpdateRequest;
import com.rohit.splitapp.persistence.dto.user.UserDTO;
import com.rohit.splitapp.service.interfaces.GroupService;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/group")
public class GroupController {

    @Autowired
    GroupService groupService;

    @Autowired
    LoggedInUser loggedInUser;

    @PostMapping("/create")
    public ResponseEntity<String> createGroup(@Valid @RequestBody GroupDTO groupDTO) {
        String response = groupService.createGroup(groupDTO);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @DeleteMapping("/delete")
    public ResponseEntity<String> deleteGroup(@RequestParam UUID groupId) {
        String response = groupService.deleteGroupByGroupId(groupId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{groupId}")
    public ResponseEntity<GroupDTO> findGroup(@PathVariable UUID groupId) {
        GroupDTO groupDTO = groupService.findGroupByGroupId(groupId);
        return ResponseEntity.status(HttpStatus.OK).body(groupDTO);
    }

    @PutMapping("/update/{groupId}")
    public ResponseEntity<String> updateGroup(@RequestBody GroupUpdateRequest groupUpdateRequest, @PathVariable UUID groupId) {
        String response = groupService.updateGroup(groupUpdateRequest, groupId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @GetMapping("")
    public ResponseEntity<GroupListDTO> findAllGroup() {
        GroupListDTO response = groupService.findAllGroup();
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/add-member/{groupId}")
    public ResponseEntity<String> addGroupMembers(@PathVariable UUID groupId, @RequestParam UUID memberId) {
        String response = groupService.addGroupMembers(groupId, memberId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @GetMapping("/{groupId}/members")
    public ResponseEntity<List<UserDTO>> findMembers(@PathVariable UUID groupId) {
        List<UserDTO> response = groupService.findMembers(groupId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @DeleteMapping("/remove-member/{groupMemberId}")
    public ResponseEntity<String> deleteMembers(@PathVariable UUID groupMemberId, @RequestParam UUID groupId) {
        String response = groupService.deleteMembers(groupId, groupMemberId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
