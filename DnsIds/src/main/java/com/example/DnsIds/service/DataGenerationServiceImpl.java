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

        // Calculate proportions based on original distribution (total: 450)
        // Original: 200 normal (44.4%), 100 flooding (22.2%), 50 NXDOMAIN (11.1%), 
        //           70 random subdomain (15.6%), 30 amplification (6.7%)
        int normalCount = Math.max(1, (int) Math.round(queryCount * 0.444));
        int floodingCount = Math.max(1, (int) Math.round(queryCount * 0.222));
        int nxdomainCount = Math.max(1, (int) Math.round(queryCount * 0.111));
        int randomSubdomainCount = Math.max(1, (int) Math.round(queryCount * 0.156));
        int amplificationCount = Math.max(1, (int) Math.round(queryCount * 0.067));
        
        // Adjust to match exact queryCount if there's a rounding difference
        int currentTotal = normalCount + floodingCount + nxdomainCount + randomSubdomainCount + amplificationCount;
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
            queries.add(q);
        }


        // 5️⃣ Amplification flood: Large payloads / TCP fallback
        for (int i = 0; i < amplificationCount; i++) {
            DnsQueryEntity q = new DnsQueryEntity();
            q.setTimestamp(timestamp);
            q.setClientIp("192.168.1.250");
            q.setClientPort(helper.randomPort());
            q.setQueryName("largepayload." + helper.randomDomain());
            q.setQueryType("TXT"); // large records
            q.setResponseCode(0);
            q.setAnswerCount(5);
            q.setRawLength(helper.randomSize(500, 1500)); // large packet
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

