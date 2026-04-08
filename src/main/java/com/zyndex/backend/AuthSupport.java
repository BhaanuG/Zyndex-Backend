package com.zyndex.backend;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
class AuthSupport {
    private final JdbcTemplate jdbc;
    private final AppProperties properties;
    final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    AuthSupport(JdbcTemplate jdbc, AppProperties properties) {
        this.jdbc = jdbc;
        this.properties = properties;
    }

    Map<String, Object> findUserByEmail(String email) {
        var rows = jdbc.queryForList("SELECT * FROM users WHERE email = ? LIMIT 1", email);
        return rows.isEmpty() ? null : rows.get(0);
    }

    Map<String, Object> findUserById(long id) {
        var rows = jdbc.queryForList("SELECT * FROM users WHERE id = ? LIMIT 1", id);
        return rows.isEmpty() ? null : rows.get(0);
    }

    Map<String, Object> requireUser(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Authentication required.");
        }
        try {
            var claims = Jwts.parser().verifyWith(secretKey()).build().parseSignedClaims(header.substring(7)).getPayload();
            Map<String, Object> user = findUserById(Long.parseLong(String.valueOf(claims.getSubject())));
            if (user == null || !Boolean.TRUE.equals(bool(user.get("active")))) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid or inactive account.");
            }
            return sanitizeUser(user);
        } catch (ApiException error) {
            throw error;
        } catch (Exception error) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid authentication token.");
        }
    }

    void requireRole(Map<String, Object> user, String role) {
        if (!role.equals(user.get("role"))) {
            throw new ApiException(HttpStatus.FORBIDDEN, "You do not have access to this resource.");
        }
    }

    String signToken(Map<String, Object> user) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(String.valueOf(user.get("id")))
                .claim("role", user.get("role"))
                .claim("email", user.get("email"))
                .claim("name", user.get("name"))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(7 * 24 * 60 * 60)))
                .signWith(secretKey())
                .compact();
    }

    Map<String, Object> sanitizeUser(Map<String, Object> row) {
        Map<String, Object> user = new LinkedHashMap<>();
        String email = str(row.get("email"));
        String role = "ADMIN".equalsIgnoreCase(str(row.get("role"))) ? "admin" : "user";
        user.put("id", number(row.get("id")));
        user.put("name", first(row.get("name"), row.get("username")));
        user.put("email", email);
        user.put("role", role);
        user.put("isPrimaryAdmin", email.equalsIgnoreCase(properties.mainAdminEmail()));
        user.put("bio", first(row.get("bio"), ""));
        user.put("registrationNo", first(row.get("registration_no"), ""));
        user.put("active", bool(row.get("active")));
        user.put("createdAt", row.get("created_at"));
        user.put("updatedAt", row.get("updated_at"));
        return user;
    }

    private SecretKey secretKey() {
        byte[] seed = properties.jwtSecret().getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[Math.max(32, seed.length)];
        System.arraycopy(seed, 0, key, 0, seed.length);
        return Keys.hmacShaKeyFor(key);
    }

    static boolean isValidEmail(String email) {
        return email != null && email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
    }

    static Object first(Object value, Object fallback) {
        if (value == null) {
            return fallback;
        }
        if (value instanceof String text && text.isBlank()) {
            return fallback;
        }
        return value;
    }

    static String str(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    static long number(Object value) {
        return value == null ? 0 : ((Number) value).longValue();
    }

    static Boolean bool(Object value) {
        if (value == null) {
            return true;
        }
        if (value instanceof Boolean b) {
            return b;
        }
        if (value instanceof Number n) {
            return n.intValue() != 0;
        }
        return Boolean.parseBoolean(String.valueOf(value));
    }
}
