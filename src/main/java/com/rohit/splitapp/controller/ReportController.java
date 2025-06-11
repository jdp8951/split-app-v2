package com.rohit.splitapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.rohit.splitapp.configuration.security.LoggedInUser;
import com.rohit.splitapp.persistence.dto.report.ReportDTO;
import com.rohit.splitapp.service.interfaces.ReportService;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/report")
public class ReportController {

    @Autowired
    ReportService reportService;

    @Autowired
    LoggedInUser loggedInUser;

    @GetMapping("/{groupId}")
    public ResponseEntity<List<ReportDTO>> generateReport(@PathVariable UUID groupId) {
        List<ReportDTO> response = reportService.generateReport(groupId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @GetMapping("/{groupId}/export")
    public ResponseEntity<byte[]> exportReport(@PathVariable UUID groupId, @RequestParam String fileType) {
        System.out.println("Export request: groupId=" + groupId + ", fileType=" + fileType);
        try {
            byte[] fileBytes = reportService.exportReport(groupId, fileType);
            System.out.println("File bytes length: " + (fileBytes != null ? fileBytes.length : "null"));
            String filename = "report." + (fileType.equalsIgnoreCase("XLSX") ? "xlsx" : "csv");
            MediaType mediaType = fileType.equalsIgnoreCase("XLSX")
                    ? MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                    : MediaType.TEXT_PLAIN;

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename)
                    .contentType(mediaType)
                    .body(fileBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .body(null);
        }
    }

}