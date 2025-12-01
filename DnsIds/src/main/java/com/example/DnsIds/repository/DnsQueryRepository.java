package com.example.DnsIds.repository;

import com.example.DnsIds.entity.DnsQueryEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DnsQueryRepository extends JpaRepository<DnsQueryEntity, Long> {
    
    List<DnsQueryEntity> findByClientIp(String clientIp);
    
    List<DnsQueryEntity> findByTimestampBetween(long startTime, long endTime);
}

