package com.neuralshield.backend.service;

import com.neuralshield.backend.model.AttackLog;
import com.neuralshield.backend.Repo.AttackLogRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AttackLogService {

    private final AttackLogRepository repository;

    public AttackLogService(AttackLogRepository repository) {
        this.repository = repository;
    }

    public AttackLog saveLog(AttackLog log) {
        return repository.save(log);
    }

    public List<AttackLog> getAllLogs() {
        return repository.findAll()
                .stream()
                .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
                .toList();
    }
}