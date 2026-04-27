package com.zyndex.backend;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
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
    private static final String RESEND_ENDPOINT = "https://api.resend.com/emails";
    private static final String GMAIL_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
    private static final String GMAIL_SEND_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send";
    private final Map<String, OtpRecord> otps = new ConcurrentHashMap<>();
    private final JavaMailSender mailSender;
    private final AppProperties properties;
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();

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
        if (hasGmailConfiguration()) {
            sendWithGmail(email, otp);
            return Map.of(
                    "message", "OTP sent successfully.",
                    "expiresInSeconds", OTP_TTL_SECONDS,
                    "emailSent", true);
        }
        if (properties.otpMailFrom() == null || properties.otpMailFrom().isBlank()) {
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "OTP SMTP email is not configured. Add OTP_SMTP_USER and OTP_SMTP_PASS in backend/.env.");
        }
        if (properties.resendApiKey() != null && !properties.resendApiKey().isBlank()) {
            sendWithResend(email, otp);
            return Map.of(
                    "message", "OTP sent successfully.",
                    "expiresInSeconds", OTP_TTL_SECONDS,
                    "emailSent", true);
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

    private boolean hasGmailConfiguration() {
        return properties.gmailClientId() != null && !properties.gmailClientId().isBlank()
                && properties.gmailClientSecret() != null && !properties.gmailClientSecret().isBlank()
                && properties.gmailRefreshToken() != null && !properties.gmailRefreshToken().isBlank()
                && properties.gmailSenderEmail() != null && !properties.gmailSenderEmail().isBlank();
    }

    private void sendWithGmail(String email, String otp) {
        String accessToken = fetchGmailAccessToken();
        String mimeMessage = """
                From: %s
                To: %s
                Subject: Your Zyndex login OTP
                Content-Type: text/plain; charset=UTF-8

                Your Zyndex login OTP is %s. This code expires in 2 minutes and can be used only once.
                """.formatted(properties.gmailSenderEmail(), email, otp);
        String raw = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(mimeMessage.getBytes(StandardCharsets.UTF_8));
        String payload = """
                {
                  "raw": "%s"
                }
                """.formatted(raw);

        HttpRequest request = HttpRequest.newBuilder(URI.create(GMAIL_SEND_ENDPOINT))
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int statusCode = response.statusCode();
            if (statusCode < 200 || statusCode >= 300) {
                throw new ApiException(HttpStatus.BAD_GATEWAY, "Could not send OTP email. Please check Gmail API configuration and try again.");
            }
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new ApiException(HttpStatus.BAD_GATEWAY, "Could not send OTP email. Please check Gmail API configuration and try again.");
        } catch (IOException error) {
            throw new ApiException(HttpStatus.BAD_GATEWAY, "Could not send OTP email. Please check Gmail API configuration and try again.");
        }
    }

    private String fetchGmailAccessToken() {
        String form = "client_id=" + urlEncode(properties.gmailClientId())
                + "&client_secret=" + urlEncode(properties.gmailClientSecret())
                + "&refresh_token=" + urlEncode(properties.gmailRefreshToken())
                + "&grant_type=refresh_token";

        HttpRequest request = HttpRequest.newBuilder(URI.create(GMAIL_TOKEN_ENDPOINT))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new ApiException(HttpStatus.BAD_GATEWAY, "Could not get Gmail access token. Please check Gmail API credentials and try again.");
            }
            Map<String, Object> responseBody = objectMapper.readValue(response.body(), new TypeReference<>() {});
            String accessToken = AuthSupport.str(responseBody.get("access_token"));
            if (accessToken.isBlank()) {
                throw new ApiException(HttpStatus.BAD_GATEWAY, "Could not get Gmail access token. Please check Gmail API credentials and try again.");
            }
            return accessToken;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new ApiException(HttpStatus.BAD_GATEWAY, "Could not get Gmail access token. Please check Gmail API credentials and try again.");
        } catch (IOException error) {
            throw new ApiException(HttpStatus.BAD_GATEWAY, "Could not get Gmail access token. Please check Gmail API credentials and try again.");
        }
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private void sendWithResend(String email, String otp) {
        String payload = """
                {
                  "from": "%s",
                  "to": ["%s"],
                  "subject": "Your Zyndex login OTP",
                  "text": "Your Zyndex login OTP is %s. This code expires in 2 minutes and can be used only once."
                }
                """.formatted(
                escapeJson(properties.otpMailFrom()),
                escapeJson(email),
                escapeJson(otp));

        HttpRequest request = HttpRequest.newBuilder(URI.create(RESEND_ENDPOINT))
                .header("Authorization", "Bearer " + properties.resendApiKey())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int statusCode = response.statusCode();
            if (statusCode < 200 || statusCode >= 300) {
                throw new ApiException(HttpStatus.BAD_GATEWAY, "Could not send OTP email. Please check Resend configuration and try again.");
            }
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new ApiException(HttpStatus.BAD_GATEWAY, "Could not send OTP email. Please check Resend configuration and try again.");
        } catch (IOException error) {
            throw new ApiException(HttpStatus.BAD_GATEWAY, "Could not send OTP email. Please check Resend configuration and try again.");
        }
    }

    private String escapeJson(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
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
