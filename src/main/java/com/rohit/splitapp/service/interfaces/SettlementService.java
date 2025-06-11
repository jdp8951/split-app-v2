package com.rohit.splitapp.service.interfaces;

import com.rohit.splitapp.persistence.dto.settlement.SettlementDTO;
import com.rohit.splitapp.persistence.dto.settlement.UserBalanceDTO;

import java.util.List;
import java.util.UUID;


public interface SettlementService {
    List<SettlementDTO> calculateSettlements(UUID groupId);
    SettlementDTO saveSettlement(SettlementDTO settlementDTO);
    List<UserBalanceDTO> getUserBalances(UUID groupId);
}


