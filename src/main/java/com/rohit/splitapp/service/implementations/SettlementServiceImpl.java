package com.rohit.splitapp.service.implementations;

import com.rohit.splitapp.persistence.dto.settlement.SettlementDTO;
import com.rohit.splitapp.persistence.dto.settlement.UserBalanceDTO;
import com.rohit.splitapp.persistence.entities.Expense;
import com.rohit.splitapp.persistence.entities.ExpenseShare;
import com.rohit.splitapp.persistence.entities.Settlement;
import com.rohit.splitapp.persistence.entities.User;
import com.rohit.splitapp.repository.ExpenseRepository;
import com.rohit.splitapp.repository.ExpenseShareRepository;
import com.rohit.splitapp.repository.SettlementRepository;
import com.rohit.splitapp.repository.UserRepository;
import com.rohit.splitapp.service.interfaces.SettlementService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class SettlementServiceImpl implements SettlementService {

    @Autowired
    private SettlementRepository settlementRepository;

    @Autowired
    private ExpenseRepository expenseRepository;

    @Autowired
    private ExpenseShareRepository expenseShareRepository;

    @Autowired
    private UserRepository userRepository;

    // Helper class
    private static class UserBalance {
        UUID userId;
        double amount;

        UserBalance(UUID userId, double amount) {
            this.userId = userId;
            this.amount = amount;
        }
    }

    @Override
    public List<SettlementDTO> calculateSettlements(UUID groupId) {
        List<Expense> expenses = expenseRepository.findByGroupId(groupId);
        Map<UUID, Double> netBalances = new HashMap<>();
        Set<UUID> userIds = new HashSet<>();

        for (Expense expense : expenses) {
            UUID payerId = expense.getPayer().getId();
            double amount = expense.getAmount();

            List<ExpenseShare> shares = expenseShareRepository.findExpenseShareById(expense.getId());

            int numberOfOwers = shares.size();
            double sharedAmount = amount / (numberOfOwers + 1);

            // ✅ Add total paid minus their own share
            netBalances.put(payerId, netBalances.getOrDefault(payerId, 0.0) + amount - sharedAmount);
            userIds.add(payerId);

            for (ExpenseShare share : shares) {
                UUID owerId = share.getUser().getId();
                netBalances.put(owerId, netBalances.getOrDefault(owerId, 0.0) - sharedAmount);
                userIds.add(owerId);
            }
        }

        List<UserBalance> creditors = new ArrayList<>();
        List<UserBalance> debtors = new ArrayList<>();
        for (UUID userId : userIds) {
            double balance = Math.round(netBalances.getOrDefault(userId, 0.0) * 100.0) / 100.0;
            if (balance > 0.01) {
                creditors.add(new UserBalance(userId, balance));
            } else if (balance < -0.01) {
                debtors.add(new UserBalance(userId, -balance));
            }
        }

        List<SettlementDTO> settlements = new ArrayList<>();
        int i = 0, j = 0;
        while (i < debtors.size() && j < creditors.size()) {
            UserBalance debtor = debtors.get(i);
            UserBalance creditor = creditors.get(j);

            double amount = Math.min(debtor.amount, creditor.amount);

            SettlementDTO dto = new SettlementDTO();
            dto.setPayerId(debtor.userId);
            dto.setPayeeId(creditor.userId);
            dto.setAmount(amount);
            dto.setDescription("Settlement for group " + groupId);
            dto.setDate(LocalDate.now().toString());
            dto.setCreatedAt(LocalDateTime.now().toString());
            settlements.add(dto);

            debtor.amount -= amount;
            creditor.amount -= amount;

            if (Math.abs(debtor.amount) < 0.01)
                i++;
            if (Math.abs(creditor.amount) < 0.01)
                j++;
        }

        return settlements;
    }

    @Override
    public SettlementDTO saveSettlement(SettlementDTO settlementDTO) {
        User payer = userRepository.findById(settlementDTO.getPayerId())
                .orElseThrow(() -> new RuntimeException("Payer not found"));
        User payee = userRepository.findById(settlementDTO.getPayeeId())
                .orElseThrow(() -> new RuntimeException("Payee not found"));

        Settlement settlement = new Settlement();
        settlement.setPayer(payer);
        settlement.setPayee(payee);
        settlement.setAmount(settlementDTO.getAmount());
        settlement.setDescription(settlementDTO.getDescription());
        settlement.setDate(settlementDTO.getDate());
        settlement.setCreatedAt(settlementDTO.getCreatedAt());

        Settlement saved = settlementRepository.save(settlement);

        SettlementDTO dto = new SettlementDTO();
        dto.setId(saved.getId());
        dto.setPayerId(saved.getPayer().getId());
        dto.setPayeeId(saved.getPayee().getId());
        dto.setAmount(saved.getAmount());
        dto.setDescription(saved.getDescription());
        dto.setDate(saved.getDate());
        dto.setCreatedAt(saved.getCreatedAt());

        return dto;
    }

    @Override
    public List<UserBalanceDTO> getUserBalances(UUID groupId) {
        List<Expense> expenses = expenseRepository.findByGroupId(groupId);
        Map<UUID, Double> netBalances = new HashMap<>();
        Set<UUID> userIds = new HashSet<>();

        for (Expense expense : expenses) {
            UUID payerId = expense.getPayer().getId();
            double amount = expense.getAmount();

            List<ExpenseShare> shares = expenseShareRepository.findExpenseShareById(expense.getId());

            int numberOfOwers = shares.size();
            double sharedAmount = amount / (numberOfOwers + 1);

            // ✅ Add total paid minus their own share
            netBalances.put(payerId, netBalances.getOrDefault(payerId, 0.0) + amount - sharedAmount);
            userIds.add(payerId);

            for (ExpenseShare share : shares) {
                UUID owerId = share.getUser().getId();
                netBalances.put(owerId, netBalances.getOrDefault(owerId, 0.0) - sharedAmount);
                userIds.add(owerId);
            }
        }

        List<UserBalanceDTO> balances = new ArrayList<>();
        for (UUID userId : userIds) {
            double balance = Math.round(netBalances.getOrDefault(userId, 0.0) * 100.0) / 100.0;
            UserBalanceDTO dto = new UserBalanceDTO();
            dto.setUserId(userId);
            dto.setBalance(balance);
            balances.add(dto);
        }

        return balances;
    }
}
