package com.zyndex.backend;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;
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
@RequestMapping("/api/resources")
class ResourceController {
    private final JdbcTemplate jdbc;
    private final AuthSupport auth;
    private final SqlSupport sql;
    private final AppProperties properties;

    ResourceController(JdbcTemplate jdbc, AuthSupport auth, SqlSupport sql, AppProperties properties) {
        this.jdbc = jdbc;
        this.auth = auth;
        this.sql = sql;
        this.properties = properties;
    }

    @GetMapping
    Map<String, Object> all(@RequestParam Map<String, String> query) {
        return list(query);
    }

    @GetMapping("/search")
    Map<String, Object> search(@RequestParam Map<String, String> query) {
        query.put("search", AuthSupport.first(query.get("query"), query.get("q")).toString());
        return list(query);
    }

    @GetMapping("/category/{category}")
    Map<String, Object> category(@PathVariable String category, @RequestParam Map<String, String> query) {
        query.put("category", category);
        return list(query);
    }

    @GetMapping("/{id}")
    Map<String, Object> one(@PathVariable long id) {
        var rows = jdbc.queryForList(resourceSelect() + " WHERE r.id = ? LIMIT 1", id);
        if (rows.isEmpty()) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Resource not found.");
        }
        return sql.mapResource(rows.get(0));
    }

    @GetMapping("/categories")
    Object categories() {
        return jdbc.queryForList("SELECT category AS name, COUNT(*) AS count FROM resources GROUP BY category ORDER BY category ASC");
    }

    @GetMapping("/stats")
    Map<String, Object> stats(HttpServletRequest request) {
        auth.requireRole(auth.requireUser(request), "admin");
        long total = jdbc.queryForObject("SELECT COUNT(*) FROM resources", Long.class);
        return Map.of(
                "totalResources", total,
                "byCategory", jdbc.queryForList("SELECT category, COUNT(*) AS total FROM resources GROUP BY category ORDER BY category ASC"),
                "recentUploads", jdbc.queryForList("SELECT id, title, category, author, created_at, updated_at FROM resources ORDER BY COALESCE(updated_at, created_at) DESC LIMIT 5"));
    }

    @GetMapping("/featured")
    Object featured(@RequestParam(defaultValue = "6") int limit) {
        limit = Math.min(Math.max(limit, 1), 20);
        return jdbc.queryForList(resourceSelect() + " ORDER BY COALESCE(r.updated_at, r.created_at) DESC LIMIT ?", limit)
                .stream().map(sql::mapResource).toList();
    }

    @PostMapping
    Map<String, Object> upload(
            HttpServletRequest request,
            @RequestParam Map<String, String> form,
            @RequestParam(value = "file", required = false) MultipartFile file) throws IOException {
        Map<String, Object> user = auth.requireUser(request);
        auth.requireRole(user, "admin");

        String title = field(form, "title");
        String category = field(form, "category");
        String subject = field(form, "subject", "author");
        String resourceType = field(form, "resourceType", "type");
        String description = field(form, "description");

        if (blank(title) || blank(category) || blank(subject) || blank(resourceType) || blank(description) || file == null || file.isEmpty()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "All resource fields and a file are required.");
        }

        String fileUrl = storeFile(file);
        jdbc.update("""
                INSERT INTO resources
                (approved, downloads_count, rating, created_at, updated_at, uploaded_by, description, author, category, file_url, image_url, title, type)
                VALUES (1, 0, 0, NOW(), NOW(), ?, ?, ?, ?, ?, NULL, ?, ?)
                """, user.get("id"), description, subject, category, fileUrl, title, SqlSupport.dbType(resourceType));
        return Map.of("message", "Resource uploaded successfully.", "resourceId", jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long.class));
    }

    @PutMapping("/{id}")
    Map<String, Object> update(
            HttpServletRequest request,
            @PathVariable long id,
            @RequestParam Map<String, String> form,
            @RequestParam(value = "file", required = false) MultipartFile file) throws IOException {
        auth.requireRole(auth.requireUser(request), "admin");
        var rows = jdbc.queryForList("SELECT * FROM resources WHERE id = ? LIMIT 1", id);
        if (rows.isEmpty()) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Resource not found.");
        }

        String title = field(form, "title");
        String category = field(form, "category");
        String subject = field(form, "subject", "author");
        String resourceType = field(form, "resourceType", "type");
        String description = field(form, "description");

        String fileUrl = AuthSupport.str(rows.get(0).get("file_url"));
        if (file != null && !file.isEmpty()) {
            fileUrl = storeFile(file);
        }
        jdbc.update("UPDATE resources SET description = ?, author = ?, category = ?, file_url = ?, title = ?, type = ?, updated_at = NOW() WHERE id = ?",
                description, subject, category, fileUrl, title, SqlSupport.dbType(resourceType), id);
        return Map.of("message", "Resource updated successfully.");
    }

    @DeleteMapping("/{id}")
    Map<String, Object> delete(HttpServletRequest request, @PathVariable long id) {
        auth.requireRole(auth.requireUser(request), "admin");
        int count = jdbc.update("DELETE FROM resources WHERE id = ?", id);
        if (count == 0) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Resource not found.");
        }
        return Map.of("message", "Resource deleted successfully.");
    }

    @GetMapping("/{id}/download")
    ResponseEntity<?> download(HttpServletRequest request, @PathVariable long id) {
        Map<String, Object> user = auth.requireUser(request);
        var rows = jdbc.queryForList("SELECT * FROM resources WHERE id = ? LIMIT 1", id);
        if (rows.isEmpty()) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Resource not found.");
        }
        String fileUrl = AuthSupport.str(rows.get(0).get("file_url"));
        jdbc.update("UPDATE resources SET downloads_count = downloads_count + 1 WHERE id = ?", id);
        jdbc.update("INSERT INTO downloads (downloaded_at, resource_id, user_id) VALUES (NOW(), ?, ?)", id, user.get("id"));
        if (fileUrl.matches("(?i)^https?://.*")) {
            return ResponseEntity.ok(Map.of("downloadUrl", fileUrl, "external", true));
        }
        Path file = Path.of(fileUrl).isAbsolute() ? Path.of(fileUrl) : Path.of(properties.uploadDir()).getParent().resolve(fileUrl).normalize();
        if (!Files.exists(file)) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Resource file is missing from the server.");
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getFileName() + "\"")
                .body(new FileSystemResource(file));
    }

    @PostMapping("/{id}/track")
    Map<String, Object> track(HttpServletRequest request, @PathVariable long id) {
        Map<String, Object> user = auth.requireUser(request);
        jdbc.update("INSERT INTO resource_views (resource_id, user_id, viewed_at) VALUES (?, ?, NOW())", id, user.get("id"));
        return Map.of("message", "Resource access tracked successfully.");
    }

    @PostMapping("/{id}/rate")
    Map<String, Object> rate(HttpServletRequest request, @PathVariable long id, @RequestBody Map<String, Object> body) {
        Map<String, Object> user = auth.requireUser(request);
        int rating = SqlSupport.parseInt(AuthSupport.str(body.get("rating")), 0);
        if (rating < 1 || rating > 5) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Rating must be between 1 and 5.");
        }
        jdbc.update("INSERT INTO feedback (rating, created_at, resource_id, user_id, comment) VALUES (?, NOW(), ?, ?, ?)",
                rating, id, user.get("id"), AuthSupport.str(body.get("comment")));
        jdbc.update("UPDATE resources SET rating = (SELECT COALESCE(AVG(rating), 0) FROM feedback WHERE resource_id = ?) WHERE id = ?", id, id);
        return Map.of("message", "Rating submitted successfully.");
    }

    @GetMapping("/{id}/ratings")
    Map<String, Object> ratings(@PathVariable long id, @RequestParam Map<String, String> query) {
        var page = sql.page(query);
        var rows = jdbc.queryForList("""
                SELECT f.id, f.rating, f.comment, f.created_at, u.username AS name, u.email
                FROM feedback f JOIN users u ON u.id = f.user_id
                WHERE f.resource_id = ? ORDER BY f.created_at DESC LIMIT ? OFFSET ?
                """, id, page.get("size"), page.get("offset"));
        var summary = jdbc.queryForList("SELECT COUNT(*) AS totalRatings, AVG(rating) AS averageRating FROM feedback WHERE resource_id = ?", id).get(0);
        return Map.of("ratings", rows, "averageRating", AuthSupport.first(summary.get("averageRating"), 0), "totalRatings", summary.get("totalRatings"), "currentPage", page.get("page"));
    }

    private Map<String, Object> list(Map<String, String> query) {
        var page = sql.page(query);
        String search = query.get("search") == null || query.get("search").isBlank() ? null : "%" + query.get("search") + "%";
        String category = query.get("category");
        String type = query.get("type") == null || "all".equals(query.get("type")) ? null : SqlSupport.dbType(query.get("type"));
        String order = "title".equals(query.get("sort")) ? "r.title ASC" : "popular".equals(query.get("sort")) ? "r.downloads_count DESC" : "COALESCE(r.updated_at, r.created_at) DESC";
        var args = new Object[] { category, category, type, type, search, search, search, search };
        var rows = jdbc.queryForList(resourceSelect() + """
                WHERE (? IS NULL OR r.category = ?)
                  AND (? IS NULL OR r.type = ?)
                  AND (? IS NULL OR r.title LIKE ? OR r.description LIKE ? OR r.author LIKE ?)
                ORDER BY %s LIMIT ? OFFSET ?
                """.formatted(order), concat(args, page.get("size"), page.get("offset")));
        long total = jdbc.queryForObject("""
                SELECT COUNT(*) FROM resources r
                WHERE (? IS NULL OR r.category = ?)
                  AND (? IS NULL OR r.type = ?)
                  AND (? IS NULL OR r.title LIKE ? OR r.description LIKE ? OR r.author LIKE ?)
                """, Long.class, args);
        return sql.pageResult("resources", rows.stream().map(sql::mapResource).toList(), total, page.get("page"), page.get("size"));
    }

    private String resourceSelect() {
        return """
                SELECT r.*, u.username AS uploader_name,
                  (SELECT COUNT(*) FROM feedback f WHERE f.resource_id = r.id) AS total_ratings,
                  (SELECT COUNT(*) FROM resource_views rv WHERE rv.resource_id = r.id) AS view_count
                FROM resources r JOIN users u ON u.id = r.uploaded_by
                """;
    }

    private String storeFile(MultipartFile file) throws IOException {
        Path dir = Path.of(properties.uploadDir()).toAbsolutePath().normalize();
        Files.createDirectories(dir);
        String extension = StringUtils.getFilenameExtension(file.getOriginalFilename());
        String name = UUID.randomUUID() + (extension == null ? "" : "." + extension);
        file.transferTo(dir.resolve(name));
        return "uploads/" + name;
    }

    private static Object[] concat(Object[] base, Object... suffix) {
        Object[] combined = new Object[base.length + suffix.length];
        System.arraycopy(base, 0, combined, 0, base.length);
        System.arraycopy(suffix, 0, combined, base.length, suffix.length);
        return combined;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static String field(Map<String, String> form, String... names) {
        for (String name : names) {
            String value = form.get(name);
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return "";
    }

    static class ResourceForm {
        public String title;
        public String category;
        public String subject;
        public String resourceType;
        public String description;
        public MultipartFile file;
    }
}
