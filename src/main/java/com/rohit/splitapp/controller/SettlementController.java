package com.rohit.splitapp.controller;

import com.rohit.splitapp.persistence.dto.settlement.SettlementDTO;
import com.rohit.splitapp.persistence.dto.settlement.UserBalanceDTO;
import com.rohit.splitapp.service.interfaces.SettlementService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/settlement")
public class SettlementController {

    @Autowired
    SettlementService settlementService;

    @GetMapping("/group/{groupId}")
    public ResponseEntity<List<SettlementDTO>> getSettlements(@PathVariable UUID groupId) {
        List<SettlementDTO> settlements = settlementService.calculateSettlements(groupId);
        return ResponseEntity.ok(settlements);
    }

    @PostMapping("")
    public ResponseEntity<SettlementDTO> saveSettlement(@RequestBody SettlementDTO settlementDTO) {
        SettlementDTO savedSettlement = settlementService.saveSettlement(settlementDTO);
        return ResponseEntity.status(201).body(savedSettlement); 
    }

    @GetMapping("/group/{groupId}/balances")
    public ResponseEntity<List<UserBalanceDTO>> getUserBalances(@PathVariable UUID groupId) {
        List<UserBalanceDTO> balances = settlementService.getUserBalances(groupId);
        return ResponseEntity.ok(balances);
    }
}