# SQL Proxy - Docker Build & Run

Complete guide for building and running the SQL Proxy using Docker.

## Prerequisites

- Docker installed and running

## Build Environment

Build the Docker image with all dependencies:

```bash
docker compose build
```

*Note: If using older Docker Compose V1, use `docker compose build` (with hyphen)*

This will:
- Install all system dependencies (PostgreSQL, Drogon, OpenSSL, etc.)
- Build libpg_query from source
- Compile the SQL Proxy service
- Create a minimal runtime image (~200MB)

## Run the Service

Start the SQL Proxy and PostgreSQL database:

```bash
docker compose up
```

The service will be available at:
- **SQL Proxy**: http://localhost:8080
- **PostgreSQL**: localhost:5432

## Stop the Service

```bash
docker compose down
```

To stop and remove volumes (database data):

```bash
docker compose down -v
```

## Rebuild After Code Changes

```bash
docker compose build --no-cache
docker compose up
```

## View Logs

```bash
docker compose logs -f sql_proxy
docker compose logs -f postgres
```

## Configuration

Edit configuration files in the `config/` directory:
- `proxy.toml` - Main proxy configuration
- `databases.toml` - Database connection settings
- `policies.toml` - Access control policies

Changes require rebuilding the Docker image.

## Health Check

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{"status":"ok","version":"1.0.0"}
```

## Testing Queries

```bash
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{
    "user": "analyst",
    "database": "analytics_db",
    "sql": "SELECT id, email FROM users LIMIT 5"
  }'
```

## Troubleshooting

### Build fails with "connection timeout"
Check that Docker has internet access for downloading dependencies.

### Container exits immediately
Check logs: `docker compose logs sql_proxy`

### Cannot connect to PostgreSQL
Ensure PostgreSQL container is running: `docker compose ps`

## Production Deployment

For production, update `docker compose.yml`:
1. Set strong PostgreSQL password
2. Configure volume mounts for persistent data
3. Add resource limits (CPU/memory)
4. Enable TLS/SSL for proxy endpoint
5. Configure external logging/monitoring
