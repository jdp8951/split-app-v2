package com.rohit.splitapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.rohit.splitapp.persistence.dto.expense.ExpenseDTO;
import com.rohit.splitapp.service.interfaces.ExpenseService;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/expense")
public class ExpenseController {

    @Autowired
    ExpenseService expenseService;

    @PostMapping("/create")
    public ResponseEntity<ExpenseDTO> createExpense(@RequestBody ExpenseDTO expenseDTO) {
        ExpenseDTO response = expenseService.createNonGroupedExpense(expenseDTO);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/create/{groupId}")
    public ResponseEntity<ExpenseDTO> createExpense(@PathVariable UUID groupId, @RequestBody ExpenseDTO expenseDTO) {
        ExpenseDTO response = expenseService.createGroupedExpense(groupId, expenseDTO);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @DeleteMapping("/delete/{expenseId}")
    public ResponseEntity<String> deleteExpense(@PathVariable UUID expenseId) {
        String response = expenseService.deleteExpenseById(expenseId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/add-ower/{expenseId}")
    public ResponseEntity<String> addOwerToExpense(@RequestParam UUID owerId, @PathVariable UUID expenseId) {
        String response = expenseService.addUserToExpense(expenseId, owerId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @DeleteMapping("/remove-ower/{expenseId}")
    public ResponseEntity<String> removeOwerFromExpense(@RequestParam UUID owerId, @PathVariable UUID expenseId) {
        String response = expenseService.removeUserFromExpense(expenseId, owerId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{expenseId}")
    public ResponseEntity<ExpenseDTO> findExpense(@PathVariable UUID expenseId) {
        ExpenseDTO response = expenseService.findExpenseById(expenseId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @GetMapping("/group/{groupId}")
    public ResponseEntity<List<ExpenseDTO>> findAllExpense(@PathVariable UUID groupId) {
        List<ExpenseDTO> response = expenseService.findAllExpense(groupId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
