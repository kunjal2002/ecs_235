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

    private static final int NXDOMAIN_THRESHOLD = 20; // Queries per second
    private static final double NXDOMAIN_RATIO_THRESHOLD = 0.7; // 70% NXDOMAIN responses

    @Override
    public List<AttackResponse> analyzeAllQueries() {
        long startTime = System.currentTimeMillis();
        List<DnsQueryEntity> getAllQueries = dnsQueryRepository.findAll();

        if(getAllQueries.isEmpty()) {
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

        // Detect both types of attacks
        List<ThreatAlert> floodingThreats = detectFlooding(getAllQueries);
        List<ThreatAlert> nxdomainThreats = detectNXDomainFlood(getAllQueries);

        // Combine all threats
        List<ThreatAlert> allThreats = new ArrayList<>();
        allThreats.addAll(floodingThreats);
        allThreats.addAll(nxdomainThreats);

        // Sort by risk score
        allThreats.sort((t1, t2) -> Integer.compare(t2.getRiskScore(), t1.getRiskScore()));

        long endTime = System.currentTimeMillis();

        String attackType = determineAttackType(floodingThreats, nxdomainThreats);

        return List.of(AttackResponse.builder()
                .attackType(attackType)
                .queriesAnalyzed(getAllQueries.size())
                .threatsDetected(allThreats.size())
                .threats(allThreats)
                .riskScore(calculateRiskScore(allThreats))
                .severity(determineSeverity(allThreats))
                .recommendation(generateRecommendation(allThreats))
                .analysisTimeMs(endTime - startTime)
                .timestamp(System.currentTimeMillis())
                .build());
    }

    private String determineAttackType(List<ThreatAlert> floodingThreats,
                                       List<ThreatAlert> nxdomainThreats) {
        boolean hasFlooding = !floodingThreats.isEmpty();
        boolean hasNXDomain = !nxdomainThreats.isEmpty();

        if (hasFlooding && hasNXDomain) return "MULTIPLE_ATTACKS_DETECTED";
        if (hasFlooding) return "FLOODING_DETECTED";
        if (hasNXDomain) return "NXDOMAIN_FLOOD_DETECTED";
        return "NO_THREATS_DETECTED";
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
            return "✅ No threats detected. All DNS queries appear normal.";
        }

        StringBuilder recommendation = new StringBuilder();


        boolean hasNXDomain = threats.stream()
                .anyMatch(t -> "NXDOMAIN_FLOOD".equals(t.getType()));
        boolean hasFlooding = threats.stream()
                .anyMatch(t -> "DNS_FLOODING".equals(t.getType()));

        recommendation.append("⚠️ Detected ").append(threats.size())
                .append(" threat(s). Recommended actions:\n\n");

        if (hasNXDomain) {
            recommendation.append("🚨 NXDOMAIN Flood Detected:\n");
            recommendation.append("1. Block or rate-limit the attacking IP addresses\n");
            recommendation.append("2. Investigate for DNS tunneling or data exfiltration\n");
            recommendation.append("3. Check for malware or botnet activity\n");
            recommendation.append("4. Implement NXDOMAIN rate limiting on DNS servers\n");
            recommendation.append("5. Monitor for reconnaissance/scanning attempts\n\n");
        }

        if (hasFlooding) {
            recommendation.append("🚨 DNS Flooding Detected:\n");
            recommendation.append("1. Implement rate limiting for the detected IP addresses\n");
            recommendation.append("2. Consider blocking or throttling these IPs temporarily\n");
            recommendation.append("3. Monitor for continued attack patterns\n");
            recommendation.append("4. Enable firewall rules to prevent DNS amplification attacks\n");
        }

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

    private List<ThreatAlert> detectNXDomainFlood(List<DnsQueryEntity> getAllQueries) {
        List<ThreatAlert> threats = new ArrayList<>();

        // Group queries by IP
        Map<String, List<DnsQueryEntity>> queriesByIp = getAllQueries.stream()
                .collect(Collectors.groupingBy(DnsQueryEntity::getClientIp));

        for (Map.Entry<String, List<DnsQueryEntity>> entry : queriesByIp.entrySet()) {
            String ip = entry.getKey();
            List<DnsQueryEntity> ipQueries = entry.getValue();

            // Count NXDOMAIN responses (response code 3)
            long nxdomainCount = ipQueries.stream()
                    .filter(q -> q.getResponseCode() == 3)
                    .count();

            // Calculate NXDOMAIN ratio
            double nxdomainRatio = (double) nxdomainCount / ipQueries.size();

            // Calculate time window
            long minTimestamp = ipQueries.stream()
                    .mapToLong(DnsQueryEntity::getTimestamp)
                    .min()
                    .orElse(0);

            long maxTimestamp = ipQueries.stream()
                    .mapToLong(DnsQueryEntity::getTimestamp)
                    .max()
                    .orElse(0);

            long timeWindowSec = Math.max(1, maxTimestamp - minTimestamp + 1);

            // Calculate NXDOMAIN queries per second
            double nxdomainPerSec = (double) nxdomainCount / timeWindowSec;

            // Detect NXDOMAIN flood: high rate OR high ratio
            if (nxdomainPerSec >= NXDOMAIN_THRESHOLD ||
                    (nxdomainRatio >= NXDOMAIN_RATIO_THRESHOLD && nxdomainCount > 10)) {

                int riskScore = calculateNXDomainRiskScore(nxdomainPerSec, nxdomainRatio);

                threats.add(new ThreatAlert(
                        "NXDOMAIN_FLOOD",
                        ip,
                        String.format("NXDOMAIN flood detected from %s: %.0f NXDOMAIN/sec (%.1f%% of queries). " +
                                        "Total NXDOMAIN: %d/%d queries over %d seconds. " +
                                        "This may indicate DNS tunneling or reconnaissance attack.",
                                ip, nxdomainPerSec, nxdomainRatio * 100,
                                nxdomainCount, ipQueries.size(), timeWindowSec),
                        riskScore
                ));
            }
        }

        // Sort by risk score
        threats.sort((t1, t2) -> Integer.compare(t2.getRiskScore(), t1.getRiskScore()));

        return threats;
    }

    private int calculateNXDomainRiskScore(double nxdomainPerSec, double ratio) {
        // Very high rate is critical
        if (nxdomainPerSec > 50) return 95;
        if (nxdomainPerSec > 30) return 90;

        // High ratio is also concerning
        if (ratio > 0.9) return 85;
        if (ratio > 0.8) return 80;
        if (ratio > 0.7) return 75;

        return 70;
    }


    @Override
    public List<DnsQueryEntity> calculate(DnsQueryEntity dnsQuery) {





        return List.of();
    }
}
