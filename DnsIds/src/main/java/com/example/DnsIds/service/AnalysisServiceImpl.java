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

        // Detect all FOUR types of attacks
        List<ThreatAlert> floodingThreats = detectFlooding(getAllQueries);
        List<ThreatAlert> nxdomainThreats = detectNXDomainFlood(getAllQueries);
        List<ThreatAlert> subdomainThreats = detectRandomSubdomainAttack(getAllQueries);
        List<ThreatAlert> amplificationThreats = detectAmplificationAttack(getAllQueries); // NEW

        // Combine all threats
        List<ThreatAlert> allThreats = new ArrayList<>();
        allThreats.addAll(floodingThreats);
        allThreats.addAll(nxdomainThreats);
        allThreats.addAll(subdomainThreats);
        allThreats.addAll(amplificationThreats); // NEW

        // Sort by risk score
        allThreats.sort((t1, t2) -> Integer.compare(t2.getRiskScore(), t1.getRiskScore()));

        long endTime = System.currentTimeMillis();

        String attackType = determineAttackType(floodingThreats, nxdomainThreats, subdomainThreats, amplificationThreats);

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
                                       List<ThreatAlert> amplificationThreats) { // NEW PARAMETER
        int attackCount = 0;
        if (!floodingThreats.isEmpty()) attackCount++;
        if (!nxdomainThreats.isEmpty()) attackCount++;
        if (!subdomainThreats.isEmpty()) attackCount++;
        if (!amplificationThreats.isEmpty()) attackCount++; // NEW

        if (attackCount > 1) return "MULTIPLE_ATTACKS_DETECTED";
        if (!floodingThreats.isEmpty()) return "FLOODING_DETECTED";
        if (!nxdomainThreats.isEmpty()) return "NXDOMAIN_FLOOD_DETECTED";
        if (!subdomainThreats.isEmpty()) return "RANDOM_SUBDOMAIN_ATTACK_DETECTED";
        if (!amplificationThreats.isEmpty()) return "DNS_AMPLIFICATION_DETECTED"; // NEW
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

        recommendation.append("⚠️ Detected ").append(threats.size())
                .append(" threat(s). Recommended actions:\n\n");

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

            // Condition 1: Large responses (>512 bytes) from single IP
            if (largeResponseCount >= LARGE_QUERY_COUNT_THRESHOLD ||
                    largeResponseRatio >= LARGE_RESPONSE_RATIO) {
                isAmplificationAttack = true;
                detectedPatterns.add(String.format("Large responses: %d queries (%.1f%%) exceed 512 bytes",
                        largeResponseCount, largeResponseRatio * 100));
            }

            // Condition 2: Too many ANY queries
            if (anyQueryCount >= ANY_QUERY_THRESHOLD || anyQueryRatio >= ANY_QUERY_RATIO) {
                isAmplificationAttack = true;
                detectedPatterns.add(String.format("Suspicious ANY queries: %d queries (%.1f%% of total)",
                        anyQueryCount, anyQueryRatio * 100));
            }

            // Condition 3: High TCP usage (indicates UDP responses too large)
            if (tcpQueryCount >= TCP_FALLBACK_THRESHOLD) {
                isAmplificationAttack = true;
                detectedPatterns.add(String.format("TCP fallback pattern: %d TCP queries (%.1f%%) - indicates large UDP responses",
                        tcpQueryCount, tcpRatio * 100));
            }

            // Condition 4: Single IP generating many large queries
            if (largeQueries.size() >= LARGE_QUERY_COUNT_THRESHOLD && avgAmplificationRatio > 5.0) {
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

    @Override
    public List<DnsQueryEntity> calculate(DnsQueryEntity dnsQuery) {


        return List.of();
    }
}
