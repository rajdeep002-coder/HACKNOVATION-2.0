package com.neuralshield.backend.Repo;

import com.neuralshield.backend.model.AttackLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AttackLogRepository extends JpaRepository<AttackLog, Long> {
}