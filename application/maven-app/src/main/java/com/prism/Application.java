package com.prism;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
public class Application {

    private static final Logger logger = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
        logger.info("PRISM Scanner - Maven/Java App started");
    }

    @GetMapping("/")
    public Map<String, Object> home() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "PRISM Scanner - Java/Maven App");
        response.put("version", "1.0.0");
        return response;
    }

    @GetMapping("/api/data")
    public Map<String, Object> getData() {
        logger.info("API endpoint called");
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("data", "sample data");
        return response;
    }
}
