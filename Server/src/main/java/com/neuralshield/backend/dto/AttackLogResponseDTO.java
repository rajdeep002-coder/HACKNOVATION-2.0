package com.neuralshield.backend.dto;

import com.neuralshield.backend.model.AttackLog;
import lombok.Data;

@Data
public class AttackLogResponseDTO {

    private Long id;
    private String timestamp;
    private String ip;
    private String type;
    private String severity;
    private int confidence;
    private int riskScore;
    private String payload;
    private boolean blocked;

    private MitreDTO mitre;

    public AttackLogResponseDTO(AttackLog log) {
        this.id = log.getId();
        this.timestamp = log.getTimestamp();
        this.ip = log.getIp();
        this.type = log.getType();
        this.severity = log.getSeverity();
        this.confidence = log.getConfidence();
        this.riskScore = log.getRiskScore();
        this.payload = log.getPayload();
        this.blocked = log.isBlocked();

        this.mitre = new MitreDTO(log.getMitre());
    }
}