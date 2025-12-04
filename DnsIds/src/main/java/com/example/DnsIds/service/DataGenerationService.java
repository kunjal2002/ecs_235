package com.example.DnsIds.service;


import com.example.DnsIds.entity.DnsQueryEntity;

import java.util.List;

public interface DataGenerationService {
    
    List<DnsQueryEntity> generateDataset(DnsQueryEntity dnsQuery, Integer queryCount);

}

