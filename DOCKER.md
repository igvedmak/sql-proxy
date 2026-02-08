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

### Admin Dashboard

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/dashboard` | Admin dashboard SPA (pass `?token=<admin_token>`) |
| `GET` | `/dashboard/api/stats` | Aggregate stats snapshot (JSON) |
| `GET` | `/dashboard/api/policies` | List all access policies (JSON) |
| `GET` | `/dashboard/api/users` | List all configured users (JSON) |
| `GET` | `/dashboard/api/alerts` | Active alerts + history (JSON) |
| `GET` | `/dashboard/api/metrics/stream` | SSE real-time metrics (2s interval) |

All dashboard endpoints require the admin token via `Authorization: Bearer <token>` header, or `?token=<token>` query parameter (for SSE/browser).

## Admin Dashboard

The proxy includes an embedded admin dashboard with real-time metrics, policy/user listing, and alert management.

**Open in browser:**
```
http://localhost:8080/dashboard?token=admin-secret-token
```

**Features:**
- Real-time request rate and audit stats charts (Chart.js + SSE)
- Policy table with name, scope, action, priority, and roles
- User table with roles
- Active alerts with severity badges
- All data auto-refreshes every 2 seconds

**Test via curl:**
```bash
# Stats snapshot
curl -H "Authorization: Bearer admin-secret-token" http://localhost:8080/dashboard/api/stats

# Policies
curl -H "Authorization: Bearer admin-secret-token" http://localhost:8080/dashboard/api/policies

# SSE stream (Ctrl+C to stop)
curl -N "http://localhost:8080/dashboard/api/metrics/stream?token=admin-secret-token"
```

## Distributed Tracing

The proxy supports W3C Trace Context propagation. Pass a `traceparent` header with your query and the proxy will:
- Parse the incoming trace context (or generate a new one)
- Include `trace_id`, `span_id`, `parent_span_id` in audit records
- Return the `traceparent` header on the response

```bash
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -H 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT 1"}'
```

## Alerting

The proxy runs a background alert evaluator that checks metrics every 10 seconds. Configure rules in `proxy.toml`:

```toml
[alerting]
enabled = true
evaluation_interval_seconds = 10
alert_log_file = "/app/logs/alerts.jsonl"

[[alerting.rules]]
name = "high_rate_limit_rejects"
condition = "rate_limit_breach"
threshold = 100
window_seconds = 60
severity = "warning"
```

View alerts via the dashboard or API:
```bash
curl -H "Authorization: Bearer admin-secret-token" http://localhost:8080/dashboard/api/alerts
```

## Audit Log Shipping

Audit records are written to pluggable sinks. The file sink is always active; webhook and syslog sinks are optional.

### File Sink (with rotation)

Enabled by default. Configure rotation in `proxy.toml`:

```toml
[audit.rotation]
max_file_size_mb = 100
max_files = 10
interval_hours = 24
time_based = true
size_based = true
```

### Webhook Sink

Ships audit records as NDJSON via HTTP POST:

```toml
[audit.webhook]
enabled = true
url = "https://siem.example.com/api/v1/events"
auth_header = "Bearer your-token-here"
timeout_ms = 5000
max_retries = 3
batch_size = 100
```

### Syslog Sink

Writes to local syslog (POSIX `syslog(3)`):

```toml
[audit.syslog]
enabled = true
ident = "sql-proxy"
```

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
