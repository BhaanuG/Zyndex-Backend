package com.zyndex.backend;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
class GlobalExceptionHandler {
    @ExceptionHandler(ApiException.class)
    ResponseEntity<Map<String, Object>> handleApi(ApiException error) {
        return ResponseEntity.status(error.status()).body(Map.of("message", error.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<Map<String, Object>> handleAny(Exception error) {
        error.printStackTrace();
        return ResponseEntity.internalServerError().body(Map.of("message", "Internal server error."));
    }
}
