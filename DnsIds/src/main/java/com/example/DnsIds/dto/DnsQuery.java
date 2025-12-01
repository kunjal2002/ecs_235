package com.example.DnsIds.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DnsQuery {
    private long timestamp;
    private String clientIp;
    private int clientPort;
    private String queryName;
    private String queryType;
    private int responseCode;
    private int answerCount;
    private int rawLength;
}

