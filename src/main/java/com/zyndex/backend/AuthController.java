package com.zyndex.backend;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.MailException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/auth")
class AuthController {
    private final JdbcTemplate jdbc;
    private final AuthSupport auth;
    private final AccountEmailService accountEmailService;

    AuthController(JdbcTemplate jdbc, AuthSupport auth, AccountEmailService accountEmailService) {
        this.jdbc = jdbc;
        this.auth = auth;
        this.accountEmailService = accountEmailService;
    }

    @PostMapping("/register")
    Map<String, Object> register(@RequestBody Map<String, Object> body) {
        String name = AuthSupport.str(body.get("name"));
        String email = AuthSupport.str(body.get("email"));
        String password = AuthSupport.str(body.get("password"));
        if (name.isBlank() || email.isBlank() || password.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Name, email, and password are required.");
        }
        if (!AuthSupport.isValidEmail(email)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Please enter a valid email address.");
        }
        if (auth.findUserByEmail(email) != null) {
            throw new ApiException(HttpStatus.CONFLICT, "An account with this email already exists.");
        }
        jdbc.update("INSERT INTO users (created_at, email, password, username, role) VALUES (NOW(), ?, ?, ?, 'STUDENT')",
                email, auth.passwordEncoder.encode(password), name);
        Map<String, Object> user = auth.sanitizeUser(auth.findUserByEmail(email));
        try {
            accountEmailService.sendSignupConfirmationEmail(name, email);
            return Map.of(
                    "message", "Account created successfully. Confirmation email sent.",
                    "user", user,
                    "confirmationEmailSent", true,
                    "confirmationEmailError", "");
        } catch (MailException error) {
            return Map.of(
                    "message", "Account created successfully, but confirmation email could not be sent.",
                    "user", user,
                    "confirmationEmailSent", false,
                    "confirmationEmailError", "Confirmation email could not be sent.");
        }
    }

    @PostMapping("/login")
    Map<String, Object> login(@RequestBody Map<String, Object> body) {
        String email = AuthSupport.str(body.get("email"));
        String password = AuthSupport.str(body.get("password"));
        String role = AuthSupport.str(body.get("role"));
        boolean preview = Boolean.TRUE.equals(body.get("preview"));
        if (email.isBlank() || password.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Email and password are required.");
        }
        if (preview && !AuthSupport.isValidEmail(email)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Entered wrong email.");
        }
        Map<String, Object> dbUser = auth.findUserByEmail(email);
        if (dbUser == null) {
            throw new ApiException(preview ? HttpStatus.NOT_FOUND : HttpStatus.UNAUTHORIZED,
                    preview ? "Entered unregistered email." : "Invalid email or password.");
        }
        if (!auth.passwordEncoder.matches(password, AuthSupport.str(dbUser.get("password")))) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, preview ? "Entered wrong password." : "Invalid email or password.");
        }
        Map<String, Object> user = auth.sanitizeUser(dbUser);
        if (!role.isBlank() && !role.equals(user.get("role"))) {
            throw new ApiException(HttpStatus.FORBIDDEN,
                    "admin".equals(role) ? "Entered wrong email for admin access." : "Entered wrong email for user access.");
        }
        if (preview) {
            return Map.of("message", "Credentials verified.", "user", user);
        }
        return Map.of("token", auth.signToken(user), "user", user);
    }

    @PostMapping("/check-login")
    Map<String, Object> checkLogin(@RequestBody Map<String, Object> body) {
        body.put("preview", true);
        return login(body);
    }

    @PostMapping("/admin-request")
    Map<String, Object> adminRequest(@RequestBody Map<String, Object> body) {
        String fullName = AuthSupport.str(body.get("fullName"));
        String displayName = AuthSupport.str(body.get("displayName"));
        String email = AuthSupport.str(body.get("email"));
        String password = AuthSupport.str(body.get("password"));
        if (fullName.isBlank() || displayName.isBlank() || email.isBlank() || password.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "All fields are required.");
        }
        if (auth.findUserByEmail(email) != null) {
            throw new ApiException(HttpStatus.CONFLICT, "An account with this email already exists.");
        }
        jdbc.update("INSERT INTO admin_requests (full_name, display_name, email, password_hash) VALUES (?, ?, ?, ?)",
                fullName, displayName, email, auth.passwordEncoder.encode(password));
        Long id = jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long.class);
        return Map.of("message", "Admin access request submitted successfully.", "requestId", id);
    }

    @PostMapping("/verify-code")
    Map<String, Object> verifyCode(@RequestBody Map<String, Object> body) {
        return Map.of("valid", AuthSupport.str(body.get("code")).matches("^\\d{6}$"));
    }

    @PostMapping("/logout")
    Map<String, Object> logout() {
        return Map.of("message", "Logged out successfully.");
    }

    @GetMapping("/me")
    Map<String, Object> me(HttpServletRequest request) {
        return auth.requireUser(request);
    }

    @PutMapping("/password")
    Map<String, Object> password(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        Map<String, Object> user = auth.requireUser(request);
        String currentPassword = AuthSupport.str(body.get("currentPassword"));
        String newPassword = AuthSupport.str(body.get("newPassword"));
        if (currentPassword.isBlank() || newPassword.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Current password and new password are required.");
        }
        Map<String, Object> dbUser = auth.findUserByEmail(AuthSupport.str(user.get("email")));
        if (!auth.passwordEncoder.matches(currentPassword, AuthSupport.str(dbUser.get("password")))) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Current password is incorrect.");
        }
        jdbc.update("UPDATE users SET password = ? WHERE id = ?", auth.passwordEncoder.encode(newPassword), user.get("id"));
        return Map.of("message", "Password updated successfully.");
    }

    @PostMapping("/forgot-password")
    Map<String, Object> forgotPassword(@RequestBody Map<String, Object> body) {
        String email = AuthSupport.str(body.get("email"));
        String fullName = AuthSupport.str(AuthSupport.first(body.get("fullName"), email.split("@")[0]));
        String role = AuthSupport.str(AuthSupport.first(body.get("role"), "user"));
        String previousPassword = AuthSupport.str(body.get("previousPassword"));
        String newPassword = AuthSupport.str(body.get("newPassword"));
        if (email.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Email is required.");
        }
        String hash = newPassword.isBlank() ? "" : auth.passwordEncoder.encode(newPassword);
        jdbc.update("INSERT INTO password_reset_requests (full_name, email, role, previous_password, new_password_hash) VALUES (?, ?, ?, ?, ?)",
                fullName, email, role, previousPassword.isBlank() ? null : previousPassword, hash);
        Map<String, Object> existing = auth.findUserByEmail(email);
        if (existing != null && !newPassword.isBlank()) {
            jdbc.update("UPDATE users SET password = ? WHERE id = ?", hash, existing.get("id"));
        }
        return Map.of("message", "Password reset request submitted successfully.");
    }

    @PostMapping("/reset-password")
    Map<String, Object> resetPassword(@RequestBody Map<String, Object> body) {
        String email = AuthSupport.str(body.get("email"));
        String newPassword = AuthSupport.str(body.get("newPassword"));
        if (email.isBlank() || newPassword.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Email and new password are required.");
        }
        Map<String, Object> user = auth.findUserByEmail(email);
        if (user == null) {
            throw new ApiException(HttpStatus.NOT_FOUND, "User not found.");
        }
        jdbc.update("UPDATE users SET password = ? WHERE id = ?", auth.passwordEncoder.encode(newPassword), user.get("id"));
        return Map.of("message", "Password reset successfully.");
    }
}
