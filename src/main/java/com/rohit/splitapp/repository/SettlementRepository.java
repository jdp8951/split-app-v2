package com.rohit.splitapp.repository;

import com.rohit.splitapp.persistence.entities.Settlement;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SettlementRepository extends JpaRepository<Settlement, java.util.UUID> {
	
}
