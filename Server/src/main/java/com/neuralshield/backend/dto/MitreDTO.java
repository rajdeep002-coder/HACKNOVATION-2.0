package com.neuralshield.backend.dto;

import com.neuralshield.backend.model.Mitre;
import lombok.Data;

@Data
public class MitreDTO {

    private String id;
    private String name;
    private String tactic;

    public MitreDTO(Mitre mitre) {
        if (mitre != null) {
            this.id = mitre.getId();
            this.name = mitre.getName();
            this.tactic = mitre.getTactic();
        }
    }
}