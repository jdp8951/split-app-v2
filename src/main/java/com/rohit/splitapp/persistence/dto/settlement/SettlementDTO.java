package com.rohit.splitapp.persistence.dto.settlement;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

import jakarta.validation.constraints.NotNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SettlementDTO {

    private UUID id;
    
    @NotNull
    private UUID payerId;

    @NotNull
    private UUID payeeId;
    
    private double amount;
    private String description;
    private String date;
    private String createdAt;
}