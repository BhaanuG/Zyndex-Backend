package com.zyndex.backend;

import org.springframework.boot.CommandLineRunner;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
class DbInitializer implements CommandLineRunner {
    private final JdbcTemplate jdbc;
    private final AppProperties properties;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    DbInitializer(JdbcTemplate jdbc, AppProperties properties) {
        this.jdbc = jdbc;
        this.properties = properties;
    }

    @Override
    public void run(String... args) {
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS users (
                  id BIGINT NOT NULL AUTO_INCREMENT,
                  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                  updated_at DATETIME(6) NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                  email VARCHAR(190) NOT NULL UNIQUE,
                  password VARCHAR(255) NOT NULL,
                  username VARCHAR(120) NOT NULL,
                  role VARCHAR(30) NOT NULL DEFAULT 'STUDENT',
                  bio TEXT NULL,
                  registration_no VARCHAR(80) NULL,
                  active BOOLEAN NOT NULL DEFAULT TRUE,
                  PRIMARY KEY (id)
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS resources (
                  id BIGINT NOT NULL AUTO_INCREMENT,
                  approved BOOLEAN NOT NULL DEFAULT TRUE,
                  downloads_count BIGINT NOT NULL DEFAULT 0,
                  rating DOUBLE NOT NULL DEFAULT 0,
                  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                  updated_at DATETIME(6) NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                  uploaded_by BIGINT NOT NULL,
                  description TEXT NULL,
                  author VARCHAR(190) NULL,
                  category VARCHAR(120) NOT NULL,
                  file_url VARCHAR(500) NULL,
                  image_url VARCHAR(500) NULL,
                  title VARCHAR(255) NOT NULL,
                  type VARCHAR(40) NOT NULL DEFAULT 'TEXTBOOK',
                  PRIMARY KEY (id),
                  CONSTRAINT fk_resources_uploaded_by FOREIGN KEY (uploaded_by) REFERENCES users(id)
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS downloads (
                  id BIGINT NOT NULL AUTO_INCREMENT,
                  downloaded_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                  resource_id BIGINT NOT NULL,
                  user_id BIGINT NOT NULL,
                  PRIMARY KEY (id),
                  CONSTRAINT fk_downloads_resource FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
                  CONSTRAINT fk_downloads_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS saved_resources (
                  resource_id BIGINT NOT NULL,
                  saved_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                  user_id BIGINT NOT NULL,
                  PRIMARY KEY (resource_id, user_id),
                  CONSTRAINT fk_saved_resource FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
                  CONSTRAINT fk_saved_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS resource_views (
                  id BIGINT NOT NULL AUTO_INCREMENT,
                  resource_id BIGINT NOT NULL,
                  user_id BIGINT NOT NULL,
                  viewed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                  PRIMARY KEY (id),
                  CONSTRAINT fk_views_resource FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
                  CONSTRAINT fk_views_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS feedback (
                  id BIGINT NOT NULL AUTO_INCREMENT,
                  rating INT NOT NULL DEFAULT 0,
                  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                  resource_id BIGINT NOT NULL,
                  user_id BIGINT NOT NULL,
                  comment TEXT NULL,
                  PRIMARY KEY (id),
                  CONSTRAINT fk_feedback_resource FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
                  CONSTRAINT fk_feedback_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS admin_requests (
                  id BIGINT NOT NULL AUTO_INCREMENT,
                  full_name VARCHAR(120) NOT NULL,
                  display_name VARCHAR(120) NOT NULL,
                  email VARCHAR(190) NOT NULL,
                  password_hash VARCHAR(255) NOT NULL,
                  status VARCHAR(30) NOT NULL DEFAULT 'pending',
                  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                  PRIMARY KEY (id)
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS contacts (
                  id BIGINT NOT NULL AUTO_INCREMENT,
                  name VARCHAR(120) NOT NULL,
                  email VARCHAR(190) NOT NULL,
                  subject VARCHAR(255) NOT NULL,
                  message TEXT NOT NULL,
                  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                  PRIMARY KEY (id)
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_requests (
                  id BIGINT NOT NULL AUTO_INCREMENT,
                  full_name VARCHAR(120) NOT NULL,
                  email VARCHAR(190) NOT NULL,
                  role VARCHAR(30) NOT NULL,
                  previous_password VARCHAR(255) NULL,
                  new_password_hash VARCHAR(255) NOT NULL,
                  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                  PRIMARY KEY (id)
                )
                """);
        tryExecute("ALTER TABLE users ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE");
        ensureMainAdmin();
    }

    private void tryExecute(String sql) {
        try {
            jdbc.execute(sql);
        } catch (DataAccessException ignored) {
        }
    }

    private void ensureMainAdmin() {
        Long id = queryLong("SELECT id FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1", properties.mainAdminEmail());
        String passwordHash = passwordEncoder.encode(properties.mainAdminPassword());
        if (id != null) {
            jdbc.update("UPDATE users SET role = 'ADMIN' WHERE id = ?", id);
            return;
        }
        jdbc.update("INSERT INTO users (created_at, email, password, username, role) VALUES (NOW(), ?, ?, ?, 'ADMIN')",
                properties.mainAdminEmail(), passwordHash, properties.mainAdminName());
    }

    private Long queryLong(String sql, Object... args) {
        var rows = jdbc.queryForList(sql, args);
        if (rows.isEmpty()) {
            return null;
        }
        Object value = rows.get(0).values().iterator().next();
        return value == null ? null : ((Number) value).longValue();
    }
}
