package com.example.DnsIds.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ThreatAlert {
    
    private String type;
    private String sourceIp;
    private String description;
    private int riskScore;
    private long timestamp;
    
    public ThreatAlert(String type, String sourceIp, String description, int riskScore) {
        this.type = type;
        this.sourceIp = sourceIp;
        this.description = description;
        this.riskScore = riskScore;
        this.timestamp = System.currentTimeMillis();
    }
}

