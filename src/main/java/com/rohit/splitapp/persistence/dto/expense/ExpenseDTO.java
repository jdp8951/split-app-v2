package com.rohit.splitapp.persistence.dto.expense;

import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import com.rohit.splitapp.persistence.dto.user.OwerDTO;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ExpenseDTO {
    private UUID expenseId;

    private String payerName;

    private UUID payerId;

    @NotNull
    private double amount;

    @NotNull
    private String description;

    private LocalDateTime date;

    private List<OwerDTO> owers;

}
