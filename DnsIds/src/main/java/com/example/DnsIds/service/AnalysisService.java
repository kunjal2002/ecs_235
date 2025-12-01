package com.example.DnsIds.service;

import com.example.DnsIds.dto.AttackResponse;
import com.example.DnsIds.entity.DnsQueryEntity;

import java.util.List;

public interface AnalysisService {

    // Analyze all queries for flooding attacks
    List<AttackResponse> analyzeAllQueries();

    // Legacy method
    List<DnsQueryEntity> calculate(DnsQueryEntity dnsQuery);
}
