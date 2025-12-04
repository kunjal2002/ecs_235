package com.example.DnsIds.controller;

import com.example.DnsIds.entity.DnsQueryEntity;
import com.example.DnsIds.service.DataGenerationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/dataset")
@CrossOrigin(origins = "*")
public class DataGenerationController {
    
    @Autowired
    private DataGenerationService dataGenerationService;
    
    @PostMapping("/generate")
    public  ResponseEntity<?> detectFlooding(
            @RequestParam(defaultValue = "100") int queryCount) {
        List<DnsQueryEntity> queries = dataGenerationService.generateDataset(null, queryCount);
        return ResponseEntity.ok("Dataset generated successfully with " + queries.size() + " queries");
    }
}

