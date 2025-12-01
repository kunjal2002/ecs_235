package com.example.DnsIds.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AttackResponse {

    private String attackType;
    private int queriesAnalyzed;
    private int threatsDetected;
    private List<ThreatAlert> threats;
    private int riskScore;
    private String severity;
    private String recommendation;
    private long analysisTimeMs;
    private long timestamp;
}

