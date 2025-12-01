package com.example.DnsIds.entity;

import jakarta.persistence.*;
import lombok.*;
@Entity
@Table(name = "dns_queries")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DnsQueryEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "timestamp")
    private long timestamp;

    @Column(name = "client_ip")
    private String clientIp;

    @Column(name = "client_port")
    private int clientPort;

    @Column(name = "query_name")
    private String queryName;

    @Column(name = "domain")
    private String domain; // extracted from queryName (e.g., youtube.com)

    @Column(name = "query_type")
    private String queryType;

    @Column(name = "response_code")
    private int responseCode;

    @Column(name = "answer_count")
    private int answerCount;

    @Column(name = "raw_length")
    private int rawLength;

    @Column(name = "query_size")
    private int querySize;

    @Column(name = "response_time")
    private double responseTime; // in milliseconds

    @Column(name = "protocol")
    private String protocol; // UDP/TCP

    @Column(name = "truncated")
    private boolean truncated; // TC flag

    @Column(name = "ttl")
    private int ttl; // Optional
}

