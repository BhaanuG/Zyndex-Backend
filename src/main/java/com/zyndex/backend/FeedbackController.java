package com.zyndex.backend;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/feedback")
class FeedbackController {
    private final JdbcTemplate jdbc;
    private final AuthSupport auth;
    private final SqlSupport sql;

    FeedbackController(JdbcTemplate jdbc, AuthSupport auth, SqlSupport sql) {
        this.jdbc = jdbc;
        this.auth = auth;
        this.sql = sql;
    }

    @PostMapping
    Map<String, Object> submit(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        Map<String, Object> user = auth.requireUser(request);
        long resourceId = AuthSupport.number(body.get("resourceId"));
        if (resourceId == 0) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "A logged-in user and resource are required.");
        }
        jdbc.update("INSERT INTO feedback (rating, created_at, resource_id, user_id, comment) VALUES (?, NOW(), ?, ?, ?)",
                SqlSupport.parseInt(AuthSupport.str(body.get("rating")), 0), resourceId, user.get("id"), AuthSupport.str(body.get("message")));
        return Map.of("message", "Feedback submitted successfully.", "feedbackId", jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long.class));
    }

    @PostMapping("/contact")
    Map<String, Object> contact(@RequestBody Map<String, Object> body) {
        String name = AuthSupport.str(body.get("name"));
        String email = AuthSupport.str(body.get("email"));
        String subject = AuthSupport.str(body.get("subject"));
        String message = AuthSupport.str(body.get("message"));
        if (name.isBlank() || email.isBlank() || subject.isBlank() || message.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "All contact fields are required.");
        }
        jdbc.update("INSERT INTO contacts (name, email, subject, message) VALUES (?, ?, ?, ?)", name, email, subject, message);
        return Map.of("message", "Message sent successfully.");
    }

    @GetMapping
    Map<String, Object> all(HttpServletRequest request, @RequestParam Map<String, String> query) {
        auth.requireRole(auth.requireUser(request), "admin");
        var page = sql.page(query);
        var rows = jdbc.queryForList("""
                SELECT f.id, f.rating, f.created_at, f.comment, u.username AS user_name, u.email, r.title, r.category
                FROM feedback f JOIN users u ON u.id = f.user_id JOIN resources r ON r.id = f.resource_id
                ORDER BY f.created_at DESC LIMIT ? OFFSET ?
                """, page.get("size"), page.get("offset"));
        long total = jdbc.queryForObject("SELECT COUNT(*) FROM feedback", Long.class);
        return sql.pageResult("feedback", rows.stream().map(row -> Map.of(
                "id", row.get("id"), "userName", row.get("user_name"), "email", row.get("email"),
                "category", row.get("category"), "comment", AuthSupport.first(row.get("comment"), ""),
                "message", AuthSupport.first(row.get("comment"), ""), "rating", row.get("rating"), "status", "reviewed",
                "date", row.get("created_at"), "resourceTitle", row.get("title"))).toList(),
                total, page.get("page"), page.get("size"));
    }

    @GetMapping("/stats")
    Map<String, Object> stats(HttpServletRequest request) {
        auth.requireRole(auth.requireUser(request), "admin");
        var total = jdbc.queryForList("SELECT COUNT(*) AS total, AVG(rating) AS averageRating FROM feedback").get(0);
        return Map.of(
                "total", AuthSupport.first(total.get("total"), 0),
                "averageRating", AuthSupport.first(total.get("averageRating"), 0),
                "byCategory", jdbc.queryForList("SELECT r.category, COUNT(*) AS total FROM feedback f JOIN resources r ON r.id = f.resource_id GROUP BY r.category ORDER BY r.category ASC"),
                "byStatus", java.util.List.of(Map.of("status", "reviewed", "total", AuthSupport.first(total.get("total"), 0))));
    }

    @GetMapping("/{id}")
    Map<String, Object> one(HttpServletRequest request, @PathVariable long id) {
        auth.requireRole(auth.requireUser(request), "admin");
        var rows = jdbc.queryForList("SELECT * FROM feedback WHERE id = ? LIMIT 1", id);
        if (rows.isEmpty()) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Feedback not found.");
        }
        return rows.get(0);
    }

    @PutMapping("/{id}/status")
    Map<String, Object> status(HttpServletRequest request) {
        auth.requireRole(auth.requireUser(request), "admin");
        return Map.of("message", "Status updates are not supported by the current schema.");
    }

    @PostMapping("/{id}/respond")
    Map<String, Object> respond(HttpServletRequest request) {
        auth.requireRole(auth.requireUser(request), "admin");
        return Map.of("message", "Admin responses are not supported by the current schema.");
    }

    @DeleteMapping("/{id}")
    Map<String, Object> delete(HttpServletRequest request, @PathVariable long id) {
        auth.requireRole(auth.requireUser(request), "admin");
        jdbc.update("DELETE FROM feedback WHERE id = ?", id);
        return Map.of("message", "Feedback deleted successfully.");
    }
}
