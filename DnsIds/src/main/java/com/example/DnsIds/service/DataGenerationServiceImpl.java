package com.example.DnsIds.service;




import com.example.DnsIds.entity.DnsQueryEntity;
import com.example.DnsIds.repository.DnsQueryRepository;
import com.example.DnsIds.util.Helper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

@Service
public class DataGenerationServiceImpl implements DataGenerationService {

    @Autowired
    private DnsQueryRepository dnsQueryRepository;

    @Autowired
    private Helper helper;

    private static final int FLOODING_THRESHOLD = 50;

    @Override
    public List<DnsQueryEntity> generateDataset(DnsQueryEntity dnsQuery, Integer queryCount) {
        // Default to 450 if not specified (maintains backward compatibility)
        if (queryCount == null || queryCount <= 0) {
            queryCount = 450;
        }

        List<DnsQueryEntity> queries = new ArrayList<>();
        long timestamp = System.currentTimeMillis() / 1000;

        // Calculate proportions for 6 attack types (total: 450 default)
        // Distribution: 35% normal, 20% flooding, 10% NXDOMAIN, 15% random subdomain, 
        //               10% amplification, 10% data exfiltration
        int normalCount = Math.max(1, (int) Math.round(queryCount * 0.35));
        int floodingCount = Math.max(1, (int) Math.round(queryCount * 0.20));
        int nxdomainCount = Math.max(1, (int) Math.round(queryCount * 0.10));
        int randomSubdomainCount = Math.max(1, (int) Math.round(queryCount * 0.15));
        int amplificationCount = Math.max(1, (int) Math.round(queryCount * 0.10));
        int exfiltrationCount = Math.max(1, (int) Math.round(queryCount * 0.10));
        
        // Adjust to match exact queryCount if there's a rounding difference
        int currentTotal = normalCount + floodingCount + nxdomainCount + randomSubdomainCount + amplificationCount + exfiltrationCount;
        int difference = queryCount - currentTotal;
        if (difference != 0) {
            normalCount += difference; // Add/subtract difference to normal traffic
        }

        // 1️⃣ Normal user traffic
        for (int i = 0; i < normalCount; i++) {
            DnsQueryEntity q = new DnsQueryEntity();
            q.setTimestamp(timestamp + i);
            q.setClientIp("192.168.1." + helper.randomInt(10, 50));
            q.setClientPort(helper.randomPort());
            q.setQueryName("www." + helper.randomDomain());
            q.setQueryType("A");
            q.setResponseCode(0); // No error
            q.setAnswerCount(1);
            q.setRawLength(helper.randomSize(100, 300));
            q.setQuerySize(helper.randomSize(40, 60)); // Normal query size
            q.setProtocol("UDP");
            queries.add(q);
        }

        // 2️⃣ Flooding attack: queries/sec from same IP
        String attackerIp = "192.168.1.100";
        for (int i = 0; i < floodingCount; i++) {
            DnsQueryEntity q = new DnsQueryEntity();
            q.setTimestamp(timestamp);
            q.setClientIp(attackerIp);
            q.setClientPort(helper.randomPort());
            q.setQueryName("www." + helper.randomDomain());
            q.setQueryType("A");
            q.setResponseCode(0);
            q.setAnswerCount(1);
            q.setRawLength(helper.randomSize(150, 250));
            q.setQuerySize(helper.randomSize(45, 55));
            q.setProtocol("UDP");
            queries.add(q);
        }

        // 3️⃣ NXDOMAIN flood: Invalid domains, high error rate
        for (int i = 0; i < nxdomainCount; i++) {
            DnsQueryEntity q = new DnsQueryEntity();
            q.setTimestamp(timestamp);
            q.setClientIp("192.168.1.150");
            q.setClientPort(helper.randomPort());
            q.setQueryName(helper.randomString(10) + ".nonexistentdomain.xyz");
            q.setQueryType("A");
            q.setResponseCode(3); // NXDOMAIN
            q.setAnswerCount(0);
            q.setRawLength(helper.randomSize(80, 120));
            q.setQuerySize(helper.randomSize(40, 55));
            q.setProtocol("UDP");
            queries.add(q);
        }

        // 4️⃣ Random subdomain flood: Many unique subdomains for same domain
        String[] prefixes = {"api", "data", "user", "cdn", "img", "login", "shop"};
        String targetDomain = "attacksite.com";

        for (int i = 0; i < randomSubdomainCount; i++) {
            String randomPrefix = prefixes[new Random().nextInt(prefixes.length)];
            String randomSubdomain = helper.randomString(6); // random part
            String fullQuery = randomPrefix + "." + randomSubdomain + "." + targetDomain;

            DnsQueryEntity q = new DnsQueryEntity();
            q.setTimestamp(timestamp);
            q.setClientIp("192.168.1.200");
            q.setClientPort(helper.randomPort());
            q.setQueryName(fullQuery);
            q.setQueryType("A");
            q.setResponseCode(0);
            q.setAnswerCount(1);
            q.setRawLength(helper.randomSize(120, 200));
            q.setQuerySize(helper.randomSize(50, 70));
            q.setProtocol("UDP");
            queries.add(q);
        }


        // 5️⃣ Amplification flood: Large payloads / ANY queries / TCP fallback
        for (int i = 0; i < amplificationCount; i++) {
            DnsQueryEntity q = new DnsQueryEntity();
            q.setTimestamp(timestamp);
            q.setClientIp("192.168.1.250");
            q.setClientPort(helper.randomPort());
            q.setQueryName("largepayload." + helper.randomDomain());
            
            // Mix of ANY and TXT queries for amplification
            q.setQueryType(i % 3 == 0 ? "ANY" : "TXT"); // 33% ANY, 67% TXT
            q.setResponseCode(0);
            q.setAnswerCount(helper.randomInt(3, 8));
            q.setRawLength(helper.randomSize(600, 1500)); // Large responses >512 bytes
            q.setQuerySize(helper.randomSize(40, 60)); // Small query size for high amplification
            
            // Some use TCP fallback (when UDP response is too large)
            q.setProtocol(i % 4 == 0 ? "TCP" : "UDP"); // 25% TCP, 75% UDP
            queries.add(q);
        }

        // 6️⃣ DNS Data Exfiltration / Tunneling: Long subdomains, Base64 encoding, high entropy
        String exfilDomain = "exfil-c2server.com";
        for (int i = 0; i < exfiltrationCount; i++) {
            DnsQueryEntity q = new DnsQueryEntity();
            q.setTimestamp(timestamp);
            q.setClientIp("192.168.1.220");
            q.setClientPort(helper.randomPort());
            
            // Create different exfiltration patterns
            String queryName;
            if (i % 3 == 0) {
                // Pattern 1: Long Base64-like encoded subdomain (simulates data encoding)
                String encodedData = helper.randomString(helper.randomInt(55, 80)); // 55-80 chars (exceeds 50 threshold)
                queryName = encodedData + "." + exfilDomain;
            } else if (i % 3 == 1) {
                // Pattern 2: Multiple fragments (simulates data fragmentation)
                String fragment1 = helper.randomString(helper.randomInt(12, 20));
                String fragment2 = helper.randomString(helper.randomInt(12, 20));
                String fragment3 = helper.randomString(helper.randomInt(12, 20));
                queryName = fragment1 + "." + fragment2 + "." + fragment3 + "." + exfilDomain;
            } else {
                // Pattern 3: High entropy subdomain (random-looking)
                String highEntropySubdomain = helper.randomString(helper.randomInt(40, 65));
                queryName = highEntropySubdomain + ".data." + exfilDomain;
            }
            
            q.setQueryName(queryName);
            // Mix of TXT (for payload) and A queries
            q.setQueryType(i % 2 == 0 ? "TXT" : "A"); // 50% TXT queries for data exfiltration
            q.setResponseCode(0);
            q.setAnswerCount(i % 2 == 0 ? helper.randomInt(2, 5) : 1);
            q.setRawLength(helper.randomSize(100, 400));
            q.setQuerySize(helper.randomSize(60, 120)); // Larger query size due to long subdomains
            q.setProtocol("UDP");
            queries.add(q);
        }

        List<DnsQueryEntity> savedQueries=dnsQueryRepository.saveAll(queries);

        String csvFilePath = "dns_flooding_dataset.csv";
        try (FileWriter writer = new FileWriter(csvFilePath)) {
            writer.append("timestamp,client_ip,client_port,query_name,query_type,response_code,answer_count,raw_length\n");
            for (DnsQueryEntity q : savedQueries) {
                writer.append(q.getTimestamp() + ","
                        + q.getClientIp() + ","
                        + q.getClientPort() + ","
                        + q.getQueryName() + ","
                        + q.getQueryType() + ","
                        + q.getResponseCode() + ","
                        + q.getAnswerCount() + ","
                        + q.getRawLength() + "\n");
            }
            writer.flush();
            System.out.println("✅ Dataset written to: " + csvFilePath);
        } catch (IOException e) {
            System.err.println("⚠️ Error writing CSV: " + e.getMessage());
        }

        return savedQueries;
    }


}

