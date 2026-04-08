# Zyndex-Backend

Spring Boot backend for the Zyndex app.

## Local Run

```powershell
./mvnw.cmd spring-boot:run
```

## Deployment

Build command: `./mvnw package -DskipTests`

Start command: `java -jar target/zyndex-spring-backend-0.0.1-SNAPSHOT.jar`

Set database, JWT, admin, SMTP, `FRONTEND_URL`, and `UPLOAD_DIR` variables in the hosting provider.
