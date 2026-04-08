package com.zyndex.backend;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.MailException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/users")
class UserController {
    private final JdbcTemplate jdbc;
    private final AuthSupport auth;
    private final SqlSupport sql;
    private final AccountEmailService accountEmailService;

    UserController(JdbcTemplate jdbc, AuthSupport auth, SqlSupport sql, AccountEmailService accountEmailService) {
        this.jdbc = jdbc;
        this.auth = auth;
        this.sql = sql;
        this.accountEmailService = accountEmailService;
    }

    @GetMapping("/{userId}/profile")
    Map<String, Object> profile(HttpServletRequest request, @PathVariable String userId) {
        Map<String, Object> user = auth.requireUser(request);
        long target = "me".equals(userId) ? AuthSupport.number(user.get("id")) : Long.parseLong(userId);
        if (target != AuthSupport.number(user.get("id")) && !"admin".equals(user.get("role"))) {
            throw new ApiException(HttpStatus.FORBIDDEN, "You can only view your own profile.");
        }
        Map<String, Object> row = auth.findUserById(target);
        if (row == null) {
            throw new ApiException(HttpStatus.NOT_FOUND, "User not found.");
        }
        return auth.sanitizeUser(row);
    }

    @PutMapping("/profile")
    Map<String, Object> updateProfile(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        Map<String, Object> user = auth.requireUser(request);
        String name = AuthSupport.str(body.get("name"));
        String email = AuthSupport.str(body.get("email"));
        if (name.isBlank() || email.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Name and email are required.");
        }
        jdbc.update("UPDATE users SET username = ?, email = ? WHERE id = ?", name, email, user.get("id"));
        Map<String, Object> updated = auth.sanitizeUser(auth.findUserById(AuthSupport.number(user.get("id"))));
        updated.put("token", auth.signToken(updated));
        return updated;
    }

    @PostMapping("/avatar")
    Map<String, Object> avatar(HttpServletRequest request, @ModelAttribute AvatarForm ignored) {
        auth.requireUser(request);
        return Map.of("avatarUrl", "");
    }

    @GetMapping("/downloads")
    Map<String, Object> downloads(HttpServletRequest request, @RequestParam Map<String, String> query) {
        Map<String, Object> user = auth.requireUser(request);
        var page = sql.page(query);
        var rows = jdbc.queryForList("""
                SELECT d.downloaded_at, r.id AS resource_id, r.title, r.category, r.author, r.type
                FROM downloads d JOIN resources r ON r.id = d.resource_id
                WHERE d.user_id = ? ORDER BY d.downloaded_at DESC LIMIT ? OFFSET ?
                """, user.get("id"), page.get("size"), page.get("offset"));
        long total = jdbc.queryForObject("SELECT COUNT(*) FROM downloads WHERE user_id = ?", Long.class, user.get("id"));
        return sql.pageResult("resources", rows.stream().map(row -> Map.of(
                "id", row.get("resource_id"), "title", row.get("title"), "category", row.get("category"),
                "subject", row.get("author"), "type", AuthSupport.str(row.get("type")).toLowerCase(), "downloadedAt", row.get("downloaded_at"))).toList(),
                total, page.get("page"), page.get("size"));
    }

    @GetMapping("/favorites")
    Map<String, Object> favorites(HttpServletRequest request, @RequestParam Map<String, String> query) {
        Map<String, Object> user = auth.requireUser(request);
        var page = sql.page(query);
        var rows = jdbc.queryForList("""
                SELECT sr.saved_at, r.id, r.title, r.category, r.author, r.type
                FROM saved_resources sr JOIN resources r ON r.id = sr.resource_id
                WHERE sr.user_id = ? ORDER BY sr.saved_at DESC LIMIT ? OFFSET ?
                """, user.get("id"), page.get("size"), page.get("offset"));
        long total = jdbc.queryForObject("SELECT COUNT(*) FROM saved_resources WHERE user_id = ?", Long.class, user.get("id"));
        return sql.pageResult("resources", rows.stream().map(row -> Map.of(
                "id", row.get("id"), "title", row.get("title"), "category", row.get("category"), "subject", row.get("author"),
                "type", AuthSupport.str(row.get("type")).toLowerCase(), "addedAt", row.get("saved_at"))).toList(), total, page.get("page"), page.get("size"));
    }

    @GetMapping("/recent-views")
    Map<String, Object> recentViews(HttpServletRequest request, @RequestParam Map<String, String> query) {
        Map<String, Object> user = auth.requireUser(request);
        var page = sql.page(query);
        var rows = jdbc.queryForList("""
                SELECT MAX(rv.viewed_at) AS viewed_at, r.id, r.title, r.category, r.author, r.type, r.description, r.file_url
                FROM resource_views rv JOIN resources r ON r.id = rv.resource_id
                WHERE rv.user_id = ?
                GROUP BY r.id, r.title, r.category, r.author, r.type, r.description, r.file_url
                ORDER BY viewed_at DESC LIMIT ? OFFSET ?
                """, user.get("id"), page.get("size"), page.get("offset"));
        long total = jdbc.queryForObject("SELECT COUNT(DISTINCT resource_id) FROM resource_views WHERE user_id = ?", Long.class, user.get("id"));
        return sql.pageResult("resources", rows.stream().map(row -> Map.of(
                "id", row.get("id"), "title", row.get("title"), "category", row.get("category"), "subject", row.get("author"),
                "author", row.get("author"), "type", AuthSupport.str(row.get("type")).toLowerCase(), "description", AuthSupport.first(row.get("description"), ""),
                "fileUrl", AuthSupport.first(row.get("file_url"), ""), "viewedAt", row.get("viewed_at"))).toList(), total, page.get("page"), page.get("size"));
    }

    @PostMapping("/favorites/{resourceId}")
    Map<String, Object> addFavorite(HttpServletRequest request, @PathVariable long resourceId) {
        Map<String, Object> user = auth.requireUser(request);
        jdbc.update("INSERT IGNORE INTO saved_resources (resource_id, saved_at, user_id) VALUES (?, NOW(), ?)", resourceId, user.get("id"));
        return Map.of("message", "Resource added to favorites.");
    }

    @DeleteMapping("/favorites/{resourceId}")
    Map<String, Object> removeFavorite(HttpServletRequest request, @PathVariable long resourceId) {
        Map<String, Object> user = auth.requireUser(request);
        jdbc.update("DELETE FROM saved_resources WHERE user_id = ? AND resource_id = ?", user.get("id"), resourceId);
        return Map.of("message", "Resource removed from favorites.");
    }

    @GetMapping("/stats")
    Map<String, Object> userStats(HttpServletRequest request) {
        Map<String, Object> user = auth.requireUser(request);
        return Map.of(
                "downloads", jdbc.queryForObject("SELECT COUNT(*) FROM downloads WHERE user_id = ?", Long.class, user.get("id")),
                "favorites", jdbc.queryForObject("SELECT COUNT(*) FROM saved_resources WHERE user_id = ?", Long.class, user.get("id")),
                "uploads", jdbc.queryForObject("SELECT COUNT(*) FROM resources WHERE uploaded_by = ?", Long.class, user.get("id")));
    }

    @GetMapping
    Map<String, Object> all(HttpServletRequest request, @RequestParam Map<String, String> query) {
        auth.requireRole(auth.requireUser(request), "admin");
        var page = sql.page(query);
        String search = "%" + AuthSupport.str(query.get("search")) + "%";
        var rows = jdbc.queryForList("SELECT id, username, email, role, created_at FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                search, search, page.get("size"), page.get("offset"));
        long total = jdbc.queryForObject("SELECT COUNT(*) FROM users WHERE username LIKE ? OR email LIKE ?", Long.class, search, search);
        return sql.pageResult("users", rows.stream().map(row -> Map.of(
                "id", row.get("id"), "name", row.get("username"), "email", row.get("email"),
                "role", "ADMIN".equals(row.get("role")) ? "admin" : "user", "registrationNo", "", "active", true, "dateJoined", row.get("created_at"))).toList(),
                total, page.get("page"), page.get("size"));
    }

    @PostMapping
    Map<String, Object> create(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        auth.requireRole(auth.requireUser(request), "admin");
        String name = AuthSupport.str(body.get("name"));
        String email = AuthSupport.str(body.get("email"));
        String password = AuthSupport.str(body.get("password"));
        if (name.isBlank() || email.isBlank() || password.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Name, email, and password are required.");
        }
        jdbc.update("INSERT INTO users (created_at, email, password, username, role) VALUES (NOW(), ?, ?, ?, ?)",
                email, auth.passwordEncoder.encode(password), name, "admin".equals(body.get("role")) ? "ADMIN" : "STUDENT");
        Long userId = jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long.class);

        try {
            accountEmailService.sendSignupConfirmationEmail(name, email);
            return Map.of(
                    "message", "User created successfully. Confirmation email sent.",
                    "userId", userId,
                    "confirmationEmailSent", true,
                    "confirmationEmailError", "");
        } catch (MailException | ApiException error) {
            return Map.of(
                    "message", "User created successfully, but confirmation email could not be sent.",
                    "userId", userId,
                    "confirmationEmailSent", false,
                    "confirmationEmailError", "Confirmation email could not be sent.");
        }
    }

    @PutMapping("/{userId}")
    Map<String, Object> update(HttpServletRequest request, @PathVariable long userId, @RequestBody Map<String, Object> body) {
        auth.requireRole(auth.requireUser(request), "admin");
        String name = AuthSupport.str(body.get("name"));
        String email = AuthSupport.str(body.get("email"));
        String role = "admin".equals(body.get("role")) ? "ADMIN" : "STUDENT";
        String password = AuthSupport.str(body.get("password"));
        if (password.isBlank()) {
            jdbc.update("UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?", name, email, role, userId);
        } else {
            jdbc.update("UPDATE users SET username = ?, email = ?, role = ?, password = ? WHERE id = ?", name, email, role, auth.passwordEncoder.encode(password), userId);
        }
        return Map.of("message", "User updated successfully.");
    }

    @PutMapping("/{userId}/role")
    Map<String, Object> updateRole(HttpServletRequest request, @PathVariable long userId, @RequestBody Map<String, Object> body) {
        auth.requireRole(auth.requireUser(request), "admin");
        jdbc.update("UPDATE users SET role = ? WHERE id = ?", "admin".equals(body.get("role")) ? "ADMIN" : "STUDENT", userId);
        return Map.of("message", "User role updated successfully.");
    }

    @PutMapping("/{userId}/status")
    Map<String, Object> updateStatus(HttpServletRequest request) {
        auth.requireRole(auth.requireUser(request), "admin");
        return Map.of("message", "Status changes are not supported by the current schema.");
    }

    @DeleteMapping("/{userId}")
    Map<String, Object> delete(HttpServletRequest request, @PathVariable long userId) {
        Map<String, Object> user = auth.requireUser(request);
        auth.requireRole(user, "admin");
        if (userId == AuthSupport.number(user.get("id"))) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "You cannot delete the account you are currently logged in with.");
        }
        jdbc.update("UPDATE resources SET uploaded_by = ? WHERE uploaded_by = ?", user.get("id"), userId);
        jdbc.update("DELETE FROM users WHERE id = ?", userId);
        return Map.of("message", "User deleted successfully.");
    }

    static class AvatarForm {
        public MultipartFile avatar;
    }
}
