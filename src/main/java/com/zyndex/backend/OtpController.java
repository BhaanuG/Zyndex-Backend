package com.zyndex.backend;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.http.HttpStatus;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class OtpController {
    private static final long OTP_TTL_SECONDS = 120;
    private static final SecureRandom RANDOM = new SecureRandom();
    private final Map<String, OtpRecord> otps = new ConcurrentHashMap<>();
    private final JavaMailSender mailSender;
    private final AppProperties properties;

    OtpController(JavaMailSender mailSender, AppProperties properties) {
        this.mailSender = mailSender;
        this.properties = properties;
    }

    @PostMapping("/api/send-otp")
    Map<String, Object> send(@RequestBody Map<String, Object> body) {
        String email = AuthSupport.str(body.get("email")).trim().toLowerCase();
        String role = AuthSupport.str(body.get("role")).trim().toLowerCase();
        if (email.isBlank() || role.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Email and role are required.");
        }
        if (!role.equals("user") && !role.equals("admin")) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Role must be user or admin.");
        }
        String otp = String.valueOf(1000 + RANDOM.nextInt(9000));
        otps.put(key(email, role), new OtpRecord(otp, Instant.now().plusSeconds(OTP_TTL_SECONDS), 0));
        if (properties.otpMailFrom() == null || properties.otpMailFrom().isBlank()) {
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "OTP SMTP email is not configured. Add OTP_SMTP_USER and OTP_SMTP_PASS in backend/.env.");
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(properties.otpMailFrom());
        message.setTo(email);
        message.setSubject("Your Zyndex login OTP");
        message.setText("Your Zyndex login OTP is " + otp + ". This code expires in 2 minutes and can be used only once.");
        try {
            mailSender.send(message);
        } catch (MailException error) {
            otps.remove(key(email, role));
            throw new ApiException(HttpStatus.BAD_GATEWAY, "Could not send OTP email. Please check SMTP credentials and try again.");
        }
        Map<String, Object> response = new HashMap<>();
        response.put("message", "OTP sent successfully.");
        response.put("expiresInSeconds", OTP_TTL_SECONDS);
        response.put("emailSent", true);
        if (properties.exposeOtpInDevelopment()) {
            response.put("devOtp", otp);
        }
        return response;
    }

    @PostMapping("/api/verify-otp")
    Map<String, Object> verify(@RequestBody Map<String, Object> body) {
        String email = AuthSupport.str(body.get("email")).trim().toLowerCase();
        String otp = AuthSupport.str(body.get("otp")).trim();
        String role = AuthSupport.str(body.get("role")).trim().toLowerCase();
        if (email.isBlank() || otp.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Email and OTP are required.");
        }
        if (!otp.matches("^\\d{4}$")) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "OTP must be a 4-digit code.");
        }
        String recordKey = role.isBlank() ? findKey(email) : key(email, role);
        OtpRecord record = recordKey == null ? null : otps.get(recordKey);
        if (record == null) {
            throw new ApiException(HttpStatus.NOT_FOUND, "OTP not found. Please request a new OTP.");
        }
        if (Instant.now().isAfter(record.expiresAt)) {
            otps.remove(recordKey);
            throw new ApiException(HttpStatus.BAD_REQUEST, "OTP expired. Please request a new OTP.");
        }
        if (record.attempts >= 5) {
            otps.remove(recordKey);
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "Maximum OTP attempts exceeded. Please request a new OTP.");
        }
        if (!record.otp.equals(otp)) {
            record.attempts += 1;
            throw new ApiException(HttpStatus.BAD_REQUEST, "Invalid OTP. " + Math.max(0, 5 - record.attempts) + " attempts remaining.");
        }
        otps.remove(recordKey);
        return Map.of("message", "OTP verified successfully.");
    }

    private String findKey(String email) {
        if (otps.containsKey(key(email, "user"))) {
            return key(email, "user");
        }
        if (otps.containsKey(key(email, "admin"))) {
            return key(email, "admin");
        }
        return null;
    }

    private String key(String email, String role) {
        return role + ":" + email;
    }

    static class OtpRecord {
        final String otp;
        final Instant expiresAt;
        int attempts;

        OtpRecord(String otp, Instant expiresAt, int attempts) {
            this.otp = otp;
            this.expiresAt = expiresAt;
            this.attempts = attempts;
        }
    }
}
