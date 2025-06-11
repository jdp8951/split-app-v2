package com.rohit.splitapp.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.rohit.splitapp.persistence.dto.group.GroupDTO;
import com.rohit.splitapp.persistence.dto.group.GroupListDTO;
import com.rohit.splitapp.persistence.dto.group.GroupUpdateRequest;
import com.rohit.splitapp.persistence.dto.user.UserDTO;

public interface GroupService {
    String createGroup(GroupDTO groupDTO);

    String deleteGroupByGroupId(UUID groupId);

    GroupDTO findGroupByGroupId(UUID groupId);

    String updateGroup(GroupUpdateRequest groupUpdateRequest, UUID groupId);

    GroupListDTO findAllGroup();

    String addGroupMembers(UUID groupId, UUID memberId);

    List<UserDTO> findMembers(UUID groupId);

    String deleteMembers(UUID groupId, UUID groupMemberId);
}
