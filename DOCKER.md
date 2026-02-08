# SQL Proxy - Docker Build & Run

Complete guide for building, running, and testing the SQL Proxy using Docker.

## Prerequisites

- Docker installed and running
- Docker Compose v2+

## Build

Build the Docker image with all dependencies:

```bash
docker compose build
```

This will:
- Install all system dependencies (PostgreSQL, Drogon, OpenSSL, etc.)
- Build libpg_query from source
- Compile the SQL Proxy service
- Create a minimal runtime image (~200MB)

## Run the Service

Start the SQL Proxy and PostgreSQL database:

```bash
docker compose up -d
```

The service will be available at:
- **SQL Proxy**: http://localhost:8080
- **PostgreSQL**: localhost:5432

## Stop the Service

```bash
docker compose down
```

To stop and remove volumes (resets database data):

```bash
docker compose down -v
```

## Testing

### Unit Tests

Build the test image and run all unit tests:

```bash
docker compose run --rm unit-tests
```

Or build directly with the test-builder stage:

```bash
docker build --target test-builder -t sql-proxy-test .
docker run --rm sql-proxy-test /build/sql_proxy/build/sql_proxy_tests --reporter compact
```

### E2E Tests

Run the full end-to-end test suite against a live proxy + PostgreSQL:

```bash
docker compose --profile e2e up --abort-on-container-exit
```

This starts PostgreSQL, the proxy, and runs `test_suite.sh` (30 tests covering queries, error handling, policies, and metrics).

To clean up E2E containers and volumes afterward:

```bash
docker compose --profile e2e down -v
```

**Important:** Always include `--profile e2e` in the `down` command. Without it, the e2e-tests container retains a stale network reference and subsequent runs will fail.

### Benchmarks

Build and run performance benchmarks (Google Benchmark):

```bash
docker build --target benchmark-builder -t sql-proxy-bench .
docker run --rm sql-proxy-bench /build/sql_proxy/build/sql_proxy_benchmarks
```

### Running Tests Locally

If the proxy and database are already running:

```bash
./test_suite.sh
```

### After Schema Changes

If you modify files in `sql/` (e.g., adding columns), the running database won't pick up the changes automatically because PostgreSQL init scripts only run on first volume creation. To apply schema changes:

```bash
docker compose down -v       # Remove volumes (drops old database)
docker compose up -d         # Recreate with updated schema
```

Or apply manually without losing data:

```bash
docker exec -i sql_proxy_postgres psql -U postgres -d testdb -c \
  "ALTER TABLE customers ADD COLUMN IF NOT EXISTS region VARCHAR(50) DEFAULT 'us-east';"
```

## Rebuild After Code Changes

```bash
docker compose build
docker compose up -d
```

Use `--no-cache` only if dependency layers need refreshing.

## View Logs

```bash
docker compose logs -f proxy
docker compose logs -f postgres
```

## Configuration

Edit configuration files in the `config/` directory:
- `proxy.toml` - Main proxy configuration (policies, rate limits, security, encryption)

Configuration is mounted read-only into the container. The proxy reads it at startup. To hot-reload policies without restart:

```bash
curl -X POST http://localhost:8080/policies/reload
```

## API Endpoints

### Core

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/query` | Execute SQL through the proxy pipeline |
| `GET` | `/health` | Health check (`{"status":"healthy"}`) |
| `GET` | `/metrics` | Prometheus-format metrics |
| `POST` | `/policies/reload` | Hot-reload policies from config |

### Compliance (Admin)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/compliance/pii-report` | PII access report (GDPR/SOC2) |
| `GET` | `/api/v1/compliance/security-summary` | Security overview |
| `GET` | `/api/v1/compliance/lineage` | Data lineage summaries |

## Testing Queries

```bash
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{
    "user": "analyst",
    "database": "testdb",
    "sql": "SELECT id, name, email FROM customers LIMIT 5"
  }'
```

## Troubleshooting

### Build fails with "connection timeout"
Check that Docker has internet access for downloading dependencies (FetchContent pulls from GitHub).

### Container exits immediately
Check logs: `docker compose logs proxy`

### Cannot connect to PostgreSQL
Ensure PostgreSQL container is healthy: `docker compose ps`

### E2E tests fail with "column does not exist"
The database schema is out of date. Recreate volumes: `docker compose down -v && docker compose up -d`

### E2E tests fail with "network not found"
The e2e-tests container has a stale network reference. Clean up with the profile flag and prune:

```bash
docker compose --profile e2e down -v && docker network prune -f
docker compose --profile e2e up --abort-on-container-exit
```

### Unit tests fail to build
Ensure the test-builder Docker stage has `BUILD_TESTS=ON`. Check `Dockerfile` for the `test-builder` target.

## Production Deployment

For production, update `docker-compose.yml`:
1. Set strong PostgreSQL password
2. Configure volume mounts for persistent data
3. Add resource limits (CPU/memory)
4. Enable TLS/SSL for proxy endpoint
5. Configure external logging/monitoring
6. Set `[encryption] enabled = true` with proper key management
7. Review `[security]` settings in `proxy.toml`
