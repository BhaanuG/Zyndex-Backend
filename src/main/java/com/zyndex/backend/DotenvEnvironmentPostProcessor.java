package com.zyndex.backend;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

public class DotenvEnvironmentPostProcessor implements EnvironmentPostProcessor {
    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        Map<String, Object> dotenv = new LinkedHashMap<>();

        for (Path path : candidateFiles()) {
            load(path, environment, dotenv);
        }

        if (!dotenv.isEmpty()) {
            environment.getPropertySources().addFirst(new MapPropertySource("zyndexDotenv", dotenv));
        }
    }

    private List<Path> candidateFiles() {
        return List.of(
                Path.of(".env"),
                Path.of("spring-backend", ".env"),
                Path.of("backend", ".env"),
                Path.of("..", ".env"),
                Path.of("..", "backend", ".env")
        );
    }

    private void load(Path path, ConfigurableEnvironment environment, Map<String, Object> dotenv) {
        Path absolutePath = path.toAbsolutePath().normalize();
        if (!Files.isRegularFile(absolutePath)) {
            return;
        }

        try {
            for (String line : Files.readAllLines(absolutePath)) {
                parse(line).forEach((key, value) -> {
                    if (environment.getProperty(key) == null && !dotenv.containsKey(key)) {
                        dotenv.put(key, value);
                    }
                });
            }
        } catch (IOException ignored) {
        }
    }

    private Map<String, String> parse(String line) {
        String trimmed = line.trim();
        if (trimmed.isBlank() || trimmed.startsWith("#") || !trimmed.contains("=")) {
            return Map.of();
        }

        int separator = trimmed.indexOf('=');
        String key = trimmed.substring(0, separator).trim();
        String value = trimmed.substring(separator + 1).trim();
        if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
            value = value.substring(1, value.length() - 1);
        }

        return key.isBlank() ? Map.of() : Map.of(key, value);
    }
}
