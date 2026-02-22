package com.neuralshield.backend.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "attack_logs")
@Data
public class AttackLog {

    @Id
    private Long id; // using frontend-generated timestamp ID

    private String timestamp;
    private String ip;
    private String type;
    private String severity;
    private int confidence;

    @Embedded
    private Mitre mitre;

    private int riskScore;

    @Column(length = 1000)
    private String payload;

    private boolean blocked;

    // Getters and Setters
}