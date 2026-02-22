package com.neuralshield.backend;

import com.neuralshield.backend.dto.AttackLogResponseDTO;
import com.neuralshield.backend.model.AttackLog;
import com.neuralshield.backend.service.AttackLogService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/logs")
@CrossOrigin(origins = "*") // allow frontend access
public class AttackLogController {

    private final AttackLogService service;

    public AttackLogController(AttackLogService service) {
        this.service = service;
    }

    //  Save log
    @PostMapping
    public AttackLog saveLog(@RequestBody AttackLog log) {


        return service.saveLog(log);
    }

    //  Fetch all logs
    @GetMapping
    public List<AttackLogResponseDTO> getAllLogs() {
        return service.getAllLogs()
                .stream()
                .map(AttackLogResponseDTO::new)
                .toList();
    }
}