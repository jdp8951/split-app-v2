package com.rohit.splitapp.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.rohit.splitapp.persistence.entities.GroupMembers;

import java.util.List;
import java.util.UUID;

public interface GroupMembersRepository extends JpaRepository<GroupMembers, UUID> {

    List<GroupMembers> findByGroupId(UUID id);

    @Query(value = "SELECT COUNT(*) > 0 AS flag FROM GroupMembers g WHERE g.group.id = ?1 AND g.member.id = ?2")
    boolean existsByGroupIdAndMemberId(UUID groupId, UUID memberId);

}
