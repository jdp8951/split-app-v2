package com.rohit.splitapp.persistence.dto.settlement;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserBalanceDTO {
    private UUID userId;
    private double balance; // Positive: owed, Negative: owes
}