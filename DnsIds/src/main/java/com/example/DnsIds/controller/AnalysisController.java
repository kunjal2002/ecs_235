package com.example.DnsIds.controller;

import com.example.DnsIds.dto.AttackResponse;
import com.example.DnsIds.service.AnalysisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/detection")
@CrossOrigin(origins = "*")
public class AnalysisController {

    @Autowired
    private AnalysisService analysisService;

    /**
     * Analyze DNS queries for flooding attacks
     * Detects IPs sending more than 100 queries/second
     */
    @PostMapping("/analysis")
    public ResponseEntity<List<AttackResponse>> detectFlooding() {
        List<AttackResponse> response = analysisService.analyzeAllQueries();
        return ResponseEntity.ok(response);
    }


}
