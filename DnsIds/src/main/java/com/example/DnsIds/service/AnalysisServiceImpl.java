package com.example.DnsIds.service;

import com.example.DnsIds.dto.AttackResponse;
import com.example.DnsIds.dto.ThreatAlert;
import com.example.DnsIds.entity.DnsQueryEntity;
import com.example.DnsIds.repository.DnsQueryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@Service
public class AnalysisServiceImpl implements AnalysisService{

    @Autowired
    private DnsQueryRepository dnsQueryRepository;

    private static final int FLOODING_THRESHOLD = 100;


    @Override
    public List<AttackResponse> analyzeAllQueries() {
        long startTime = System.currentTimeMillis();
        //detect flooding
        List<DnsQueryEntity> getAllQueries= dnsQueryRepository.findAll();
        //build AttackResponse
        if(getAllQueries.isEmpty())
        {
            return List.of(AttackResponse.builder()
                    .attackType("NONE")
                    .queriesAnalyzed(0)
                    .threatsDetected(0)
                    .threats(new ArrayList<>())
                    .riskScore(0)
                    .severity("NONE")
                    .recommendation("No queries found in database. Generate dataset first.")
                    .analysisTimeMs(System.currentTimeMillis() - startTime)
                    .timestamp(System.currentTimeMillis())
                    .build());
        }
        List<ThreatAlert> threats = detectFlooding(getAllQueries);

        long endTime = System.currentTimeMillis();

        return List.of(AttackResponse.builder()
                .attackType(threats.isEmpty() ? "NO_FLOODING" : "FLOODING_DETECTED")
                .queriesAnalyzed(getAllQueries.size())
                .threatsDetected(threats.size())
                .threats(threats)
                .riskScore(calculateRiskScore(threats))
                .severity(determineSeverity(threats))
                .recommendation(generateRecommendation(threats))
                .analysisTimeMs(endTime - startTime)
                .timestamp(System.currentTimeMillis())
                .build());

    }

    private List<ThreatAlert> detectFlooding(List<DnsQueryEntity> getAllQueries) {
        List<ThreatAlert> threats = new ArrayList<>();

        //get all the ip address

        Map<String, List<DnsQueryEntity>> queriesByIp = getAllQueries.stream()
                .collect(Collectors.groupingBy(DnsQueryEntity::getClientIp));

        // Analyze each IP for flooding behavior(If in one second we are getting request from the same clientIp then its a flooding behaviour)
        for (Map.Entry<String, List<DnsQueryEntity>> entry : queriesByIp.entrySet()) {
            String ip = entry.getKey();
            List<DnsQueryEntity> ipQueries = entry.getValue();

            // Calculate window
            //eg : start
            long minTimestamp = ipQueries.stream()
                    .mapToLong(DnsQueryEntity::getTimestamp)
                    .min()
                    .orElse(0);

            long maxTimestamp = ipQueries.stream()
                    .mapToLong(DnsQueryEntity::getTimestamp)
                    .max()
                    .orElse(0);

            // Time window in seconds (minimum 1 second to avoid division by zero)
            long timeWindowSec = Math.max(1, maxTimestamp - minTimestamp + 1);

            // Calculate queries per second
            double queriesPerSec = (double) ipQueries.size() / timeWindowSec;

            // Check if it exceeds flooding threshold
            if (queriesPerSec >= FLOODING_THRESHOLD) {
                int riskScore = calculateFloodingRiskScore(queriesPerSec);

                threats.add(new ThreatAlert(
                        "DNS_FLOODING",
                        ip,
                        String.format("High volume flooding detected: %.0f queries/sec from %s (threshold: %d/sec). Total queries: %d over %d seconds.",
                                queriesPerSec, ip, FLOODING_THRESHOLD, ipQueries.size(), timeWindowSec),
                        riskScore
                ));
            }
        }

        // Sort threats by risk score (highest first)
        threats.sort((t1, t2) -> Integer.compare(t2.getRiskScore(), t1.getRiskScore()));

        return threats;



    }
    private int calculateRiskScore(List<ThreatAlert> threats) {
        if (threats.isEmpty()) return 0;

        // Return the highest risk score
        return threats.stream()
                .mapToInt(ThreatAlert::getRiskScore)
                .max()
                .orElse(0);
    }

    private String determineSeverity(List<ThreatAlert> threats) {
        int maxRisk = calculateRiskScore(threats);

        if (maxRisk >= 90) return "CRITICAL";
        if (maxRisk >= 75) return "HIGH";
        if (maxRisk >= 50) return "MEDIUM";
        if (maxRisk > 0) return "LOW";
        return "NONE";
    }

    private String generateRecommendation(List<ThreatAlert> threats) {
        if (threats.isEmpty()) {
            return "✅ No flooding detected. All IPs are within normal query rates.";
        }

        StringBuilder recommendation = new StringBuilder();
        recommendation.append("⚠️ Detected ").append(threats.size())
                .append(" flooding source(s). Recommended actions:\n");

        recommendation.append("1. Implement rate limiting for the detected IP addresses\n");
        recommendation.append("2. Consider blocking or throttling these IPs temporarily\n");
        recommendation.append("3. Monitor for continued attack patterns\n");
        recommendation.append("4. Enable firewall rules to prevent DNS amplification attacks");

        return recommendation.toString();
    }

    private int calculateFloodingRiskScore(double queriesPerSec) {
        // Risk score based on how much the threshold is exceeded
        if (queriesPerSec > 500) return 95;  // Critical
        if (queriesPerSec > 300) return 90;  // Very High
        if (queriesPerSec > 200) return 85;  // High
        if (queriesPerSec > 150) return 75;  // Medium-High
        return 70;  // Medium
    }


    @Override
    public List<DnsQueryEntity> calculate(DnsQueryEntity dnsQuery) {





        return List.of();
    }
}
