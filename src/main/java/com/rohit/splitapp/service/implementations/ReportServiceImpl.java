package com.rohit.splitapp.service.implementations;

import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import com.rohit.splitapp.exception.DataNotFoundException;
import com.rohit.splitapp.persistence.dto.report.ReportDTO;
import com.rohit.splitapp.persistence.dto.report.TempReport;
import com.rohit.splitapp.persistence.entities.Group;
import com.rohit.splitapp.persistence.entities.User;
import com.rohit.splitapp.repository.ExpenseShareRepository;
import com.rohit.splitapp.repository.GroupRepository;
import com.rohit.splitapp.repository.UserRepository;
import com.rohit.splitapp.service.interfaces.ReportService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class ReportServiceImpl implements ReportService {

    @Autowired
    private AuthorizationService authorizationService;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ExpenseShareRepository expenseShareRepository;

    @Override
    public List<ReportDTO> generateReport(UUID groupId) {
        Group group = groupRepository.findById(groupId).orElseThrow(() -> new DataNotFoundException("Group not found"));
        List<TempReport> tempReportList = groupRepository.generateReportById(group.getId());
        List<ReportDTO> reportDTOS = new ArrayList<>();

        for (TempReport tempReport : tempReportList) {
            ReportDTO reportDTO = new ReportDTO();
            reportDTO.setExpenseOwner(tempReport.getExpenseOwner());
            reportDTO.setExpenseName(tempReport.getExpenseName());
            reportDTO.setGroupName(tempReport.getGroupName());
            reportDTO.setTotalExpenseAmount(tempReport.getTotalExpenseAmount());
            List<String> contributors = expenseShareRepository.findPayersById(tempReport.getExpenseId());
            reportDTO.setExpenseContributors(contributors);
            reportDTOS.add(reportDTO);
        }
        return reportDTOS;
    }

    @Override
    public byte[] exportReport(UUID groupId, String fileType) {
        User user = authorizationService.getAuthorizedUser();
        Group group = groupRepository.findById(groupId).orElseThrow(() -> new DataNotFoundException("Group not found"));
        if (user == null || user.getId() != group.getUser().getId()) throw new AccessDeniedException("Access Denied");

        if ("XLSX".equalsIgnoreCase(fileType)) {
            return exportToXLSX(groupId);
        } else if ("CSV".equalsIgnoreCase(fileType)) {
            return exportToCSV(groupId);
        } else {
            throw new RuntimeException("Invalid file type");
        }
    }

    private byte[] exportToCSV(UUID groupId) {
        List<TempReport> tempReportList = groupRepository.generateReportById(groupId);
        List<ReportDTO> reportDTOS = new ArrayList<>();
        for (TempReport tempReport : tempReportList) {
            ReportDTO reportDTO = new ReportDTO();
            reportDTO.setExpenseOwner(tempReport.getExpenseOwner());
            reportDTO.setExpenseName(tempReport.getExpenseName());
            reportDTO.setGroupName(tempReport.getGroupName());
            reportDTO.setTotalExpenseAmount(tempReport.getTotalExpenseAmount());
            List<String> contributors = expenseShareRepository.findPayersById(tempReport.getExpenseId());
            reportDTO.setExpenseContributors(contributors);
            reportDTOS.add(reportDTO);
        }

        StringBuilder csvData = new StringBuilder();
        csvData.append("groupName,expenseName,expenseOwner,expenseContributors,totalExpenseAmount\n");
        for (ReportDTO reportDTO : reportDTOS) {
            csvData.append("\"").append(reportDTO.getGroupName()).append("\",");
            csvData.append("\"").append(reportDTO.getExpenseName()).append("\",");
            csvData.append("\"").append(reportDTO.getExpenseOwner()).append("\",");
            csvData.append("\"").append(String.join(",", reportDTO.getExpenseContributors())).append("\",");
            csvData.append(reportDTO.getTotalExpenseAmount()).append("\n");
        }
        return csvData.toString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] exportToXLSX(UUID groupId) {
        List<TempReport> tempReportList = groupRepository.generateReportById(groupId);
        List<ReportDTO> reportDTOS = new ArrayList<>();
        for (TempReport tempReport : tempReportList) {
            ReportDTO reportDTO = new ReportDTO();
            reportDTO.setExpenseOwner(tempReport.getExpenseOwner());
            reportDTO.setExpenseName(tempReport.getExpenseName());
            reportDTO.setGroupName(tempReport.getGroupName());
            reportDTO.setTotalExpenseAmount(tempReport.getTotalExpenseAmount());
            List<String> contributors = expenseShareRepository.findPayersById(tempReport.getExpenseId());
            reportDTO.setExpenseContributors(contributors);
            reportDTOS.add(reportDTO);
        }

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            Workbook workbook = new XSSFWorkbook();
            Sheet sheet = workbook.createSheet("Data");
            int rowNum = 0;
            Row headerRow = sheet.createRow(rowNum++);
            headerRow.createCell(0).setCellValue("groupName");
            headerRow.createCell(1).setCellValue("expenseName");
            headerRow.createCell(2).setCellValue("expenseOwner");
            headerRow.createCell(3).setCellValue("expenseContributors");
            headerRow.createCell(4).setCellValue("totalExpenseAmount");
            for (ReportDTO reportDTO : reportDTOS) {
                Row row = sheet.createRow(rowNum++);
                row.createCell(0).setCellValue(reportDTO.getGroupName());
                row.createCell(1).setCellValue(reportDTO.getExpenseName());
                row.createCell(2).setCellValue(reportDTO.getExpenseOwner());
                row.createCell(3).setCellValue(String.join(",", reportDTO.getExpenseContributors()));
                row.createCell(4).setCellValue(reportDTO.getTotalExpenseAmount());
            }
            workbook.write(outputStream);
            workbook.close();
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}