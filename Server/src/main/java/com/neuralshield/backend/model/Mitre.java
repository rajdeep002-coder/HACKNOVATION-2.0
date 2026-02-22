package com.neuralshield.backend.model;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

@Embeddable
public class Mitre {

    @Column(name = "mitre_id")
    private String id;

    @Column(name = "mitre_name")
    private String name;

    @Column(name = "mitre_tactic")
    private String tactic;

    public Mitre() {}

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getTactic() {
        return tactic;
    }

    public void setTactic(String tactic) {
        this.tactic = tactic;
    }
}