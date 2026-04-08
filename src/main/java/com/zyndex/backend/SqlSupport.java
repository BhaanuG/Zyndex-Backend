package com.zyndex.backend;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.stereotype.Component;

@Component
class SqlSupport {
    Map<String, Integer> page(Map<String, String> query) {
        int page = Math.max(parseInt(query.get("page"), 0), 0);
        int size = Math.min(Math.max(parseInt(query.get("size"), 10), 1), 100);
        return Map.of("page", page, "size", size, "offset", page * size);
    }

    Map<String, Object> pageResult(String key, Object items, long total, int page, int size) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put(key, items);
        result.put("totalPages", (long) Math.ceil(total / (double) size));
        result.put("totalElements", total);
        result.put("currentPage", page);
        return result;
    }

    Map<String, Object> mapResource(Map<String, Object> row) {
        String fileUrl = AuthSupport.str(row.get("file_url"));
        String type = AuthSupport.str(row.get("type")).toLowerCase();
        Map<String, Object> resource = new LinkedHashMap<>();
        resource.put("id", AuthSupport.number(row.get("id")));
        resource.put("title", row.get("title"));
        resource.put("category", row.get("category"));
        resource.put("subject", row.get("author"));
        resource.put("author", row.get("author"));
        resource.put("type", type);
        resource.put("resourceType", type);
        resource.put("description", AuthSupport.first(row.get("description"), ""));
        resource.put("fileName", fileUrl.isBlank() ? "" : Path.of(fileUrl).getFileName().toString());
        resource.put("fileUrl", fileUrl);
        resource.put("hasDownload", !fileUrl.isBlank());
        resource.put("isExternalFile", fileUrl.matches("(?i)^https?://.*"));
        resource.put("downloadCount", AuthSupport.number(AuthSupport.first(row.get("downloads_count"), 0)));
        resource.put("viewCount", AuthSupport.number(AuthSupport.first(row.get("view_count"), 0)));
        resource.put("featured", AuthSupport.bool(row.get("approved")));
        resource.put("uploadedBy", row.get("uploaded_by"));
        resource.put("uploadedByName", row.get("uploader_name"));
        resource.put("createdAt", row.get("created_at"));
        resource.put("updatedAt", AuthSupport.first(row.get("updated_at"), row.get("created_at")));
        resource.put("averageRating", row.get("rating") == null ? 0 : ((Number) row.get("rating")).doubleValue());
        resource.put("totalRatings", AuthSupport.number(AuthSupport.first(row.get("total_ratings"), 0)));
        return resource;
    }

    static String dbType(String resourceType) {
        if ("article".equalsIgnoreCase(resourceType)) {
            return "PAPER";
        }
        if ("pdf".equalsIgnoreCase(resourceType)) {
            return "GUIDE";
        }
        return "TEXTBOOK";
    }

    static int parseInt(String value, int fallback) {
        try {
            return value == null || value.isBlank() ? fallback : Integer.parseInt(value);
        } catch (NumberFormatException error) {
            return fallback;
        }
    }
}
