package com.rohit.splitapp.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.rohit.splitapp.persistence.dto.expense.ExpenseDTO;

public interface ExpenseService {
    ExpenseDTO createNonGroupedExpense(ExpenseDTO expenseDTO);

    ExpenseDTO createGroupedExpense(UUID groupId, ExpenseDTO expenseDTO);

    String deleteExpenseById(UUID expenseId);

    String addUserToExpense(UUID expenseId, UUID owerId);

    String removeUserFromExpense(UUID expenseId, UUID owerId);

    ExpenseDTO findExpenseById(UUID expenseId);

    List<ExpenseDTO> findAllExpense(UUID groupId);

}
