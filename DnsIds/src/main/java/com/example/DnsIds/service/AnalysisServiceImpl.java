package com.example.DnsIds.service;

import com.example.DnsIds.dto.AttackResponse;
import com.example.DnsIds.dto.ThreatAlert;
import com.example.DnsIds.entity.DnsQueryEntity;
import com.example.DnsIds.repository.DnsQueryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@Service
public class AnalysisServiceImpl implements AnalysisService{

    @Autowired
    private DnsQueryRepository dnsQueryRepository;

    private static final int FLOODING_THRESHOLD = 100;
    private static final int SUBDOMAIN_THRESHOLD = 30; // Unique subdomains
    private static final double SUBDOMAIN_UNIQUENESS_RATIO = 0.8; // 80% unique

    private static final int NXDOMAIN_THRESHOLD = 20; // Queries per second
    private static final double NXDOMAIN_RATIO_THRESHOLD = 0.7; // 70% NXDOMAIN responses

    // DNS Amplification Attack thresholds (Cloudflare/Datadog patterns)
    private static final int LARGE_RESPONSE_THRESHOLD = 512; // bytes - Standard DNS UDP limit
    private static final int ANY_QUERY_THRESHOLD = 10; // Number of ANY queries from single IP
    private static final double ANY_QUERY_RATIO = 0.3; // 30% ANY queries is suspicious
    private static final int TCP_FALLBACK_THRESHOLD = 15; // Too many TCP queries (UDP overflow)
    private static final int LARGE_QUERY_COUNT_THRESHOLD = 20; // Large queries from single IP
    private static final double LARGE_RESPONSE_RATIO = 0.5; // 50% of queries have large responses
    
    // Adaptive thresholds for smaller datasets
    private int getAdaptiveLargeQueryThreshold(int totalQueries) {
        return Math.min(LARGE_QUERY_COUNT_THRESHOLD, Math.max(5, totalQueries / 5)); // At least 5, or 20% of queries
    }
    
    private int getAdaptiveAnyQueryThreshold(int totalQueries) {
        return Math.min(ANY_QUERY_THRESHOLD, Math.max(3, totalQueries / 10)); // At least 3, or 10% of queries
    }
    
    private int getAdaptiveTcpThreshold(int totalQueries) {
        return Math.min(TCP_FALLBACK_THRESHOLD, Math.max(5, totalQueries / 7)); // At least 5, or ~14% of queries
    }

    // DNS Data Exfiltration / Tunneling thresholds
    private static final int SUBDOMAIN_LENGTH_THRESHOLD = 50; // Suspicious subdomain length
    private static final double ENTROPY_THRESHOLD = 4.5; // High entropy indicates randomness
    private static final int TXT_QUERY_THRESHOLD = 15; // Too many TXT queries
    private static final double TXT_QUERY_RATIO = 0.4; // 40% TXT queries is suspicious
    private static final int UNIQUE_SUBDOMAIN_EXFIL_THRESHOLD = 40; // Unique subdomains per domain
    private static final int BASE64_MIN_LENGTH = 20; // Minimum length to check Base64
    
    // Adaptive thresholds for smaller datasets
    private int getAdaptiveTxtThreshold(int totalQueries) {
        return Math.min(TXT_QUERY_THRESHOLD, Math.max(3, totalQueries / 7)); // At least 3, or ~14% of queries
    }
    
    private int getAdaptiveUniqueSubdomainThreshold(int totalQueries) {
        return Math.min(UNIQUE_SUBDOMAIN_EXFIL_THRESHOLD, Math.max(5, totalQueries / 2)); // At least 5, or 50% of queries
    }

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

        // Detect all FIVE types of attacks
        List<ThreatAlert> floodingThreats = detectFlooding(getAllQueries);
        List<ThreatAlert> nxdomainThreats = detectNXDomainFlood(getAllQueries);
        List<ThreatAlert> subdomainThreats = detectRandomSubdomainAttack(getAllQueries);
        List<ThreatAlert> amplificationThreats = detectAmplificationAttack(getAllQueries);
        List<ThreatAlert> exfiltrationThreats = detectDataExfiltration(getAllQueries); // NEW

        // Combine all threats
        List<ThreatAlert> allThreats = new ArrayList<>();
        allThreats.addAll(floodingThreats);
        allThreats.addAll(nxdomainThreats);
        allThreats.addAll(subdomainThreats);
        allThreats.addAll(amplificationThreats);
        allThreats.addAll(exfiltrationThreats); // NEW

        // Sort by risk score
        allThreats.sort((t1, t2) -> Integer.compare(t2.getRiskScore(), t1.getRiskScore()));

        long endTime = System.currentTimeMillis();

        String attackType = determineAttackType(floodingThreats, nxdomainThreats, subdomainThreats, amplificationThreats, exfiltrationThreats);

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
                                       List<ThreatAlert> nxdomainThreats,
                                       List<ThreatAlert> subdomainThreats,
                                       List<ThreatAlert> amplificationThreats,
                                       List<ThreatAlert> exfiltrationThreats) { // NEW PARAMETER
        int attackCount = 0;
        if (!floodingThreats.isEmpty()) attackCount++;
        if (!nxdomainThreats.isEmpty()) attackCount++;
        if (!subdomainThreats.isEmpty()) attackCount++;
        if (!amplificationThreats.isEmpty()) attackCount++;
        if (!exfiltrationThreats.isEmpty()) attackCount++; // NEW

        if (attackCount > 1) return "MULTIPLE_ATTACKS_DETECTED";
        if (!floodingThreats.isEmpty()) return "FLOODING_DETECTED";
        if (!nxdomainThreats.isEmpty()) return "NXDOMAIN_FLOOD_DETECTED";
        if (!subdomainThreats.isEmpty()) return "RANDOM_SUBDOMAIN_ATTACK_DETECTED";
        if (!amplificationThreats.isEmpty()) return "DNS_AMPLIFICATION_DETECTED";
        if (!exfiltrationThreats.isEmpty()) return "DNS_DATA_EXFILTRATION_DETECTED"; // NEW
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

        // Check for different attack types
        boolean hasNXDomain = threats.stream()
                .anyMatch(t -> "NXDOMAIN_FLOOD".equals(t.getType()));
        boolean hasFlooding = threats.stream()
                .anyMatch(t -> "DNS_FLOODING".equals(t.getType()));
        boolean hasRandomSubdomain = threats.stream()
                .anyMatch(t -> "RANDOM_SUBDOMAIN_ATTACK".equals(t.getType()));
        boolean hasAmplification = threats.stream()
                .anyMatch(t -> "DNS_AMPLIFICATION".equals(t.getType()));
        boolean hasExfiltration = threats.stream()
                .anyMatch(t -> "DNS_DATA_EXFILTRATION".equals(t.getType()));

        recommendation.append("⚠️ Detected ").append(threats.size())
                .append(" threat(s). Recommended actions:\n\n");

        // Data Exfiltration recommendations (HIGHEST PRIORITY - DATA THEFT)
        if (hasExfiltration) {
            recommendation.append("🔥 DNS DATA EXFILTRATION DETECTED (CRITICAL - Data Theft in Progress):\n");
            recommendation.append("1. IMMEDIATELY isolate and block the attacking IP from network\n");
            recommendation.append("2. Block DNS queries to suspicious external domains\n");
            recommendation.append("3. Implement DNS query length limits (block subdomains >50 chars)\n");
            recommendation.append("4. Enable entropy-based filtering on DNS firewall\n");
            recommendation.append("5. Restrict TXT query types unless business-critical\n");
            recommendation.append("6. Investigate compromised host for malware/backdoors\n");
            recommendation.append("7. Check what data may have been exfiltrated (logs, traffic analysis)\n");
            recommendation.append("8. Implement DNS-over-HTTPS (DoH) to prevent tunneling abuse\n");
            recommendation.append("9. Alert Security Operations Center (SOC) - incident response needed\n");
            recommendation.append("10. Review firewall rules - data may be leaking through DNS\n\n");
        }

        // Amplification attack recommendations (HIGHEST PRIORITY)
        if (hasAmplification) {
            recommendation.append("🔥 DNS AMPLIFICATION ATTACK (CRITICAL - Cloudflare/Datadog Pattern):\n");
            recommendation.append("1. IMMEDIATELY implement Response Rate Limiting (RRL)\n");
            recommendation.append("2. Block or severely rate-limit ANY query types\n");
            recommendation.append("3. Disable recursion on authoritative nameservers\n");
            recommendation.append("4. Implement BCP38 filtering (anti-spoofing) at network edge\n");
            recommendation.append("5. Enable DNS cookies (RFC 7873) to prevent source IP spoofing\n");
            recommendation.append("6. Monitor outbound traffic for reflection to victim IPs\n");
            recommendation.append("7. Consider blocking queries that result in responses >512 bytes on UDP\n");
            recommendation.append("8. Alert SOC/NOC team - this may be part of active DDoS campaign\n");
            recommendation.append("9. Check if your DNS server is on public resolver lists (remove if yes)\n\n");
        }

        if (hasRandomSubdomain) {
            recommendation.append("🚨 Random Subdomain Attack Detected:\n");
            recommendation.append("1. Implement rate limiting per domain for the attacking IP\n");
            recommendation.append("2. Block queries with high entropy/random subdomains\n");
            recommendation.append("3. Enable response rate limiting (RRL) on DNS servers\n");
            recommendation.append("4. Monitor for DNS tunneling or data exfiltration attempts\n");
            recommendation.append("5. Consider implementing QNAME minimization\n");
            recommendation.append("6. Use DNS firewall rules to detect pattern anomalies\n\n");
        }

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

    private List<ThreatAlert> detectRandomSubdomainAttack(List<DnsQueryEntity> getAllQueries) {
        List<ThreatAlert> threats = new ArrayList<>();

        // Group queries by IP
        Map<String, List<DnsQueryEntity>> queriesByIp = getAllQueries.stream()
                .collect(Collectors.groupingBy(DnsQueryEntity::getClientIp));

        for (Map.Entry<String, List<DnsQueryEntity>> entry : queriesByIp.entrySet()) {
            String ip = entry.getKey();
            List<DnsQueryEntity> ipQueries = entry.getValue();

            // Group queries by base domain for this IP
            Map<String, List<String>> domainToSubdomains = new HashMap<>();

            for (DnsQueryEntity query : ipQueries) {
                String queryName = query.getQueryName();
                if (queryName == null || queryName.isEmpty()) continue;

                // Extract base domain (e.g., "sub1.sub2.example.com" -> "example.com")
                String baseDomain = extractBaseDomain(queryName);

                // Store the full query name (subdomain)
                domainToSubdomains
                        .computeIfAbsent(baseDomain, k -> new ArrayList<>())
                        .add(queryName);
            }

            // Analyze each base domain for random subdomain patterns
            for (Map.Entry<String, List<String>> domainEntry : domainToSubdomains.entrySet()) {
                String baseDomain = domainEntry.getKey();
                List<String> subdomains = domainEntry.getValue();

                // Count unique subdomains
                long uniqueCount = subdomains.stream().distinct().count();
                double uniquenessRatio = (double) uniqueCount / subdomains.size();

                // Calculate time window
                List<DnsQueryEntity> domainQueries = ipQueries.stream()
                        .filter(q -> q.getQueryName() != null &&
                                extractBaseDomain(q.getQueryName()).equals(baseDomain))
                        .collect(Collectors.toList());

                long minTimestamp = domainQueries.stream()
                        .mapToLong(DnsQueryEntity::getTimestamp)
                        .min()
                        .orElse(0);

                long maxTimestamp = domainQueries.stream()
                        .mapToLong(DnsQueryEntity::getTimestamp)
                        .max()
                        .orElse(0);

                long timeWindowSec = Math.max(1, maxTimestamp - minTimestamp + 1);

                // Calculate queries per second
                double queriesPerSec = (double) subdomains.size() / timeWindowSec;

                // Detect attack: many unique subdomains with high uniqueness ratio
                if (uniqueCount >= SUBDOMAIN_THRESHOLD &&
                        uniquenessRatio >= SUBDOMAIN_UNIQUENESS_RATIO) {

                    int riskScore = calculateSubdomainRiskScore(uniqueCount, uniquenessRatio, queriesPerSec);

                    threats.add(new ThreatAlert(
                            "RANDOM_SUBDOMAIN_ATTACK",
                            ip,
                            String.format("Random subdomain attack detected from %s targeting '%s': " +
                                            "%d unique subdomains out of %d queries (%.1f%% unique) over %d seconds. " +
                                            "Rate: %.1f queries/sec. This attack bypasses DNS caching and increases server load.",
                                    ip, baseDomain, uniqueCount, subdomains.size(),
                                    uniquenessRatio * 100, timeWindowSec, queriesPerSec),
                            riskScore
                    ));
                }
            }
        }

        // Sort by risk score
        threats.sort((t1, t2) -> Integer.compare(t2.getRiskScore(), t1.getRiskScore()));

        return threats;
    }

    /**
     * Extracts the base domain from a full query name
     * e.g., "api.xyz123.attacksite.com" -> "attacksite.com"
     * e.g., "www.google.com" -> "google.com"
     */
    private String extractBaseDomain(String queryName) {
        if (queryName == null || queryName.isEmpty()) {
            return "";
        }

        // Remove trailing dot if present
        if (queryName.endsWith(".")) {
            queryName = queryName.substring(0, queryName.length() - 1);
        }

        String[] parts = queryName.split("\\.");

        // If less than 2 parts, return as is
        if (parts.length < 2) {
            return queryName;
        }

        // Return last 2 parts as base domain (e.g., "example.com")
        // This is a simplified approach; for production, use a public suffix list
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    private int calculateSubdomainRiskScore(long uniqueCount, double uniquenessRatio, double queriesPerSec) {
        int score = 70; // Base score

        // High number of unique subdomains
        if (uniqueCount > 100) score += 15;
        else if (uniqueCount > 70) score += 10;
        else if (uniqueCount > 50) score += 5;

        // Very high uniqueness ratio (indicates randomness)
        if (uniquenessRatio > 0.95) score += 10;
        else if (uniquenessRatio > 0.9) score += 5;

        // High query rate
        if (queriesPerSec > 50) score += 10;
        else if (queriesPerSec > 30) score += 5;

        return Math.min(score, 100); // Cap at 100
    }

    /**
     * Detects DNS Amplification Attacks using Cloudflare/Datadog patterns:
     * 1. DNS responses larger than 512 bytes
     * 2. Too many "ANY" queries
     * 3. High number of TCP-based DNS responses (when UDP is too small)
     * 4. A single IP sending many large queries
     */
    private List<ThreatAlert> detectAmplificationAttack(List<DnsQueryEntity> getAllQueries) {
        List<ThreatAlert> threats = new ArrayList<>();

        // Group queries by IP
        Map<String, List<DnsQueryEntity>> queriesByIp = getAllQueries.stream()
                .collect(Collectors.groupingBy(DnsQueryEntity::getClientIp));

        for (Map.Entry<String, List<DnsQueryEntity>> entry : queriesByIp.entrySet()) {
            String ip = entry.getKey();
            List<DnsQueryEntity> ipQueries = entry.getValue();

            // PATTERN 1: DNS responses larger than 512 bytes
            long largeResponseCount = ipQueries.stream()
                    .filter(q -> q.getRawLength() > LARGE_RESPONSE_THRESHOLD)
                    .count();
            double largeResponseRatio = (double) largeResponseCount / ipQueries.size();

            // PATTERN 2: Too many "ANY" queries
            long anyQueryCount = ipQueries.stream()
                    .filter(q -> "ANY".equals(q.getQueryType()))
                    .count();
            double anyQueryRatio = (double) anyQueryCount / ipQueries.size();

            // PATTERN 3: High number of TCP-based DNS responses (UDP fallback)
            long tcpQueryCount = ipQueries.stream()
                    .filter(q -> "TCP".equalsIgnoreCase(q.getProtocol()))
                    .count();
            double tcpRatio = (double) tcpQueryCount / ipQueries.size();

            // PATTERN 4: A single IP sending many large queries
            List<DnsQueryEntity> largeQueries = ipQueries.stream()
                    .filter(q -> q.getRawLength() > LARGE_RESPONSE_THRESHOLD)
                    .collect(Collectors.toList());

            // Calculate amplification ratio for large queries
            double avgAmplificationRatio = 0.0;
            double maxAmplificationRatio = 0.0;

            if (!largeQueries.isEmpty()) {
                avgAmplificationRatio = largeQueries.stream()
                        .filter(q -> q.getQuerySize() > 0)
                        .mapToDouble(q -> (double) q.getRawLength() / q.getQuerySize())
                        .average()
                        .orElse(0);

                maxAmplificationRatio = largeQueries.stream()
                        .filter(q -> q.getQuerySize() > 0)
                        .mapToDouble(q -> (double) q.getRawLength() / q.getQuerySize())
                        .max()
                        .orElse(0);
            }

            // DETECTION LOGIC - Flag if ANY of these conditions are met:
            boolean isAmplificationAttack = false;
            List<String> detectedPatterns = new ArrayList<>();
            
            // Use adaptive thresholds based on dataset size
            int adaptiveLargeThreshold = getAdaptiveLargeQueryThreshold(ipQueries.size());
            int adaptiveAnyThreshold = getAdaptiveAnyQueryThreshold(ipQueries.size());
            int adaptiveTcpThreshold = getAdaptiveTcpThreshold(ipQueries.size());

            // Condition 1: Large responses (>512 bytes) from single IP
            if (largeResponseCount >= adaptiveLargeThreshold ||
                    largeResponseRatio >= LARGE_RESPONSE_RATIO) {
                isAmplificationAttack = true;
                detectedPatterns.add(String.format("Large responses: %d queries (%.1f%%) exceed 512 bytes",
                        largeResponseCount, largeResponseRatio * 100));
            }

            // Condition 2: Too many ANY queries
            if (anyQueryCount >= adaptiveAnyThreshold || anyQueryRatio >= ANY_QUERY_RATIO) {
                isAmplificationAttack = true;
                detectedPatterns.add(String.format("Suspicious ANY queries: %d queries (%.1f%% of total)",
                        anyQueryCount, anyQueryRatio * 100));
            }

            // Condition 3: High TCP usage (indicates UDP responses too large)
            if (tcpQueryCount >= adaptiveTcpThreshold) {
                isAmplificationAttack = true;
                detectedPatterns.add(String.format("TCP fallback pattern: %d TCP queries (%.1f%%) - indicates large UDP responses",
                        tcpQueryCount, tcpRatio * 100));
            }

            // Condition 4: Single IP generating many large queries
            if (largeQueries.size() >= adaptiveLargeThreshold && avgAmplificationRatio > 5.0) {
                isAmplificationAttack = true;
                detectedPatterns.add(String.format("High amplification from single IP: %d large queries with avg %.1fx amplification",
                        largeQueries.size(), avgAmplificationRatio));
            }

            // If attack detected, create threat alert
            if (isAmplificationAttack) {
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
                double queriesPerSec = (double) ipQueries.size() / timeWindowSec;

                // Calculate average response size
                double avgResponseSize = ipQueries.stream()
                        .mapToInt(DnsQueryEntity::getRawLength)
                        .average()
                        .orElse(0);

                int riskScore = calculateAmplificationRiskScore(
                        largeResponseCount,
                        anyQueryCount,
                        tcpQueryCount,
                        avgAmplificationRatio,
                        maxAmplificationRatio
                );

                // Build description with all detected patterns
                StringBuilder description = new StringBuilder();
                description.append(String.format("🚨 DNS AMPLIFICATION ATTACK from %s\n\n", ip));
                description.append(String.format("Total Queries: %d over %d seconds (%.1f queries/sec)\n",
                        ipQueries.size(), timeWindowSec, queriesPerSec));
                description.append(String.format("Average Response Size: %.0f bytes\n\n", avgResponseSize));
                description.append("Detected Attack Patterns:\n");

                for (int i = 0; i < detectedPatterns.size(); i++) {
                    description.append(String.format("  %d. %s\n", i + 1, detectedPatterns.get(i)));
                }

                if (avgAmplificationRatio > 0) {
                    description.append(String.format("\nAmplification Ratio: Avg %.1fx | Max %.1fx\n",
                            avgAmplificationRatio, maxAmplificationRatio));
                }

                description.append("\n⚠️ This pattern matches DNS reflection/amplification DDoS attacks used by major botnets.");

                threats.add(new ThreatAlert(
                        "DNS_AMPLIFICATION",
                        ip,
                        description.toString(),
                        riskScore
                ));
            }
        }

        // Sort by risk score (highest first)
        threats.sort((t1, t2) -> Integer.compare(t2.getRiskScore(), t1.getRiskScore()));

        return threats;
    }

    /**
     * Calculates risk score for DNS Amplification attacks
     * Based on Cloudflare/Datadog detection patterns
     */
    private int calculateAmplificationRiskScore(long largeResponseCount,
                                                long anyQueryCount,
                                                long tcpQueryCount,
                                                double avgAmplification,
                                                double maxAmplification) {
        int score = 0;

        // PATTERN 1: Large responses (>512 bytes)
        if (largeResponseCount > 100) score += 25;
        else if (largeResponseCount > 50) score += 20;
        else if (largeResponseCount > 20) score += 15;
        else if (largeResponseCount > 10) score += 10;

        // PATTERN 2: ANY queries (highly suspicious)
        if (anyQueryCount > 50) score += 30; // CRITICAL
        else if (anyQueryCount > 30) score += 25;
        else if (anyQueryCount > 10) score += 20;
        else if (anyQueryCount > 0) score += 10;

        // PATTERN 3: TCP fallback pattern
        if (tcpQueryCount > 50) score += 20;
        else if (tcpQueryCount > 30) score += 15;
        else if (tcpQueryCount > 15) score += 10;

        // PATTERN 4: High amplification ratio
        if (avgAmplification > 50) score += 20;
        else if (avgAmplification > 30) score += 15;
        else if (avgAmplification > 10) score += 10;
        else if (avgAmplification > 5) score += 5;

        // Extreme max amplification bonus
        if (maxAmplification > 100) score += 5;

        return Math.min(score, 100); // Cap at 100
    }

    /**
     * Detects DNS Data Exfiltration / Tunneling
     * Patterns:
     * 1. Long or random-looking subdomains (high entropy)
     * 2. High query frequency to same domain with different subdomains
     * 3. Repeated TXT queries
     * 4. Base32/Base64 encoded patterns in subdomains
     */
    private List<ThreatAlert> detectDataExfiltration(List<DnsQueryEntity> getAllQueries) {
        List<ThreatAlert> threats = new ArrayList<>();

        // Group queries by IP
        Map<String, List<DnsQueryEntity>> queriesByIp = getAllQueries.stream()
                .collect(Collectors.groupingBy(DnsQueryEntity::getClientIp));

        for (Map.Entry<String, List<DnsQueryEntity>> entry : queriesByIp.entrySet()) {
            String ip = entry.getKey();
            List<DnsQueryEntity> ipQueries = entry.getValue();

            // PATTERN 1 & 4: Long subdomains with high entropy / Base64 patterns
            List<DnsQueryEntity> suspiciousSubdomains = ipQueries.stream()
                    .filter(q -> q.getQueryName() != null && !q.getQueryName().isEmpty())
                    .filter(q -> {
                        String subdomain = extractSubdomain(q.getQueryName());
                        double entropy = calculateEntropy(subdomain);
                        boolean isLong = subdomain.length() > SUBDOMAIN_LENGTH_THRESHOLD;
                        boolean highEntropy = entropy > ENTROPY_THRESHOLD;
                        boolean looksEncoded = looksLikeBase64(subdomain);
                        return isLong || highEntropy || looksEncoded;
                    })
                    .collect(Collectors.toList());

            // PATTERN 2: High frequency of unique subdomains to same base domain
            Map<String, List<String>> domainToSubdomains = new HashMap<>();
            for (DnsQueryEntity query : ipQueries) {
                if (query.getQueryName() == null || query.getQueryName().isEmpty()) continue;
                String baseDomain = extractBaseDomain(query.getQueryName());
                String fullSubdomain = extractSubdomain(query.getQueryName());
                domainToSubdomains
                        .computeIfAbsent(baseDomain, k -> new ArrayList<>())
                        .add(fullSubdomain);
            }

            // PATTERN 3: Too many TXT queries (used for data exfiltration)
            long txtQueryCount = ipQueries.stream()
                    .filter(q -> "TXT".equalsIgnoreCase(q.getQueryType()))
                    .count();
            double txtQueryRatio = (double) txtQueryCount / ipQueries.size();

            // Analyze patterns
            boolean hasExfiltrationPattern = false;
            List<String> detectedPatterns = new ArrayList<>();
            double maxEntropy = 0.0;
            int maxSubdomainLength = 0;
            String mostSuspiciousDomain = "";

            // Check Pattern 1 & 4: Suspicious subdomains
            // This should trigger if ANY queries have long subdomains, high entropy, or look encoded
            if (!suspiciousSubdomains.isEmpty()) {
                hasExfiltrationPattern = true;

                for (DnsQueryEntity q : suspiciousSubdomains) {
                    String subdomain = extractSubdomain(q.getQueryName());
                    double entropy = calculateEntropy(subdomain);
                    if (entropy > maxEntropy) {
                        maxEntropy = entropy;
                        mostSuspiciousDomain = q.getQueryName();
                    }
                    if (subdomain.length() > maxSubdomainLength) {
                        maxSubdomainLength = subdomain.length();
                    }
                }

                detectedPatterns.add(String.format(
                        "Suspicious subdomains: %d queries with long/high-entropy/encoded subdomains (max length: %d, max entropy: %.2f)",
                        suspiciousSubdomains.size(), maxSubdomainLength, maxEntropy));
            }

            // Check Pattern 2: Many unique subdomains per domain (tunneling behavior)
            int adaptiveUniqueThreshold = getAdaptiveUniqueSubdomainThreshold(ipQueries.size());
            for (Map.Entry<String, List<String>> domainEntry : domainToSubdomains.entrySet()) {
                String baseDomain = domainEntry.getKey();
                long uniqueSubdomains = domainEntry.getValue().stream().distinct().count();

                if (uniqueSubdomains >= adaptiveUniqueThreshold) {
                    hasExfiltrationPattern = true;
                    detectedPatterns.add(String.format(
                            "Data tunneling pattern: %d unique subdomains to '%s' (indicates data fragmentation)",
                            uniqueSubdomains, baseDomain));
                }
            }

            // Check Pattern 3: TXT query abuse
            int adaptiveTxtThreshold = getAdaptiveTxtThreshold(ipQueries.size());
            if (txtQueryCount >= adaptiveTxtThreshold || txtQueryRatio >= TXT_QUERY_RATIO) {
                hasExfiltrationPattern = true;
                detectedPatterns.add(String.format(
                        "TXT query abuse: %d TXT queries (%.1f%% of total) - TXT records can carry arbitrary payloads",
                        txtQueryCount, txtQueryRatio * 100));
            }

            // If exfiltration pattern detected, create threat alert
            if (hasExfiltrationPattern) {
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
                double queriesPerSec = (double) ipQueries.size() / timeWindowSec;

                int riskScore = calculateExfiltrationRiskScore(
                        suspiciousSubdomains.size(),
                        maxEntropy,
                        maxSubdomainLength,
                        txtQueryCount,
                        domainToSubdomains.values().stream()
                                .mapToLong(list -> list.stream().distinct().count())
                                .max()
                                .orElse(0)
                );

                // Build description
                StringBuilder description = new StringBuilder();
                description.append(String.format("🚨 DNS DATA EXFILTRATION / TUNNELING from %s\n\n", ip));
                description.append(String.format("Total Queries: %d over %d seconds (%.1f queries/sec)\n\n",
                        ipQueries.size(), timeWindowSec, queriesPerSec));
                description.append("Detected Exfiltration Patterns:\n");

                for (int i = 0; i < detectedPatterns.size(); i++) {
                    description.append(String.format("  %d. %s\n", i + 1, detectedPatterns.get(i)));
                }

                if (maxEntropy > 0) {
                    description.append(String.format("\nMost Suspicious Query: %s (entropy: %.2f)\n",
                            mostSuspiciousDomain, maxEntropy));
                }

                description.append("\n⚠️ Potential data theft in progress! ");
                description.append("Attackers may be encoding sensitive data (passwords, tokens, files) ");
                description.append("in DNS queries to bypass firewall restrictions.");

                threats.add(new ThreatAlert(
                        "DNS_DATA_EXFILTRATION",
                        ip,
                        description.toString(),
                        riskScore
                ));
            }
        }

        // Sort by risk score (highest first)
        threats.sort((t1, t2) -> Integer.compare(t2.getRiskScore(), t1.getRiskScore()));

        return threats;
    }

    /**
     * Calculate Shannon entropy to detect randomness in strings
     * Higher entropy = more random = more suspicious
     */
    private double calculateEntropy(String str) {
        if (str == null || str.isEmpty()) return 0.0;

        Map<Character, Integer> frequencyMap = new HashMap<>();
        for (char c : str.toCharArray()) {
            frequencyMap.put(c, frequencyMap.getOrDefault(c, 0) + 1);
        }

        double entropy = 0.0;
        int length = str.length();

        for (int count : frequencyMap.values()) {
            double probability = (double) count / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        return entropy;
    }

    /**
     * Extract subdomain from full query name
     * e.g., "abc123def.malicious.example.com" -> "abc123def.malicious"
     */
    private String extractSubdomain(String queryName) {
        if (queryName == null || queryName.isEmpty()) return "";

        // Remove trailing dot
        if (queryName.endsWith(".")) {
            queryName = queryName.substring(0, queryName.length() - 1);
        }

        String[] parts = queryName.split("\\.");

        // If only 2 parts (example.com), no subdomain
        if (parts.length <= 2) return "";

        // Return everything except last 2 parts (base domain)
        StringBuilder subdomain = new StringBuilder();
        for (int i = 0; i < parts.length - 2; i++) {
            if (i > 0) subdomain.append(".");
            subdomain.append(parts[i]);
        }

        return subdomain.toString();
    }

    /**
     * Check if string looks like Base64/Base32 encoded data
     */
    private boolean looksLikeBase64(String str) {
        if (str == null || str.length() < BASE64_MIN_LENGTH) return false;

        // Base64 uses: A-Z, a-z, 0-9, +, /, = (padding)
        // Base32 uses: A-Z, 2-7, = (padding)
        // Check if string is mostly these characters
        String base64Pattern = "^[A-Za-z0-9+/=_-]+$";

        if (!str.matches(base64Pattern)) return false;

        // Additional check: high ratio of alphanumeric chars
        long alphanumericCount = str.chars()
                .filter(c -> Character.isLetterOrDigit(c))
                .count();

        double ratio = (double) alphanumericCount / str.length();

        // If >90% alphanumeric and passes pattern, likely encoded
        return ratio > 0.9;
    }

    /**
     * Calculate risk score for data exfiltration
     */
    private int calculateExfiltrationRiskScore(int suspiciousSubdomainCount,
                                              double maxEntropy,
                                              int maxSubdomainLength,
                                              long txtQueryCount,
                                              long maxUniqueSubdomains) {
        int score = 0;

        // Suspicious subdomains with high entropy
        if (suspiciousSubdomainCount > 50) score += 25;
        else if (suspiciousSubdomainCount > 30) score += 20;
        else if (suspiciousSubdomainCount > 10) score += 15;
        else if (suspiciousSubdomainCount > 0) score += 10;

        // Very high entropy (very random)
        if (maxEntropy > 5.5) score += 20;
        else if (maxEntropy > 5.0) score += 15;
        else if (maxEntropy > 4.5) score += 10;

        // Extremely long subdomains (data hiding)
        if (maxSubdomainLength > 100) score += 15;
        else if (maxSubdomainLength > 70) score += 10;
        else if (maxSubdomainLength > 50) score += 5;

        // TXT query abuse
        if (txtQueryCount > 50) score += 20;
        else if (txtQueryCount > 30) score += 15;
        else if (txtQueryCount > 15) score += 10;

        // Many unique subdomains (tunneling/fragmentation)
        if (maxUniqueSubdomains > 100) score += 15;
        else if (maxUniqueSubdomains > 60) score += 10;
        else if (maxUniqueSubdomains > 40) score += 5;

        return Math.min(score, 100); // Cap at 100
    }

    @Override
    public List<DnsQueryEntity> calculate(DnsQueryEntity dnsQuery) {


        return List.of();
    }
}
