# SQL Proxy — Features and Improvements Roadmap

This document outlines potential features and improvements for the SQL Proxy system, organized by category. Each item represents a concrete, implementable enhancement that addresses real production concerns.

---

## Multi-Tenancy & Scale

### 4. Distributed Rate Limiting
**Problem:** In-memory rate limiter is single-node. Multi-node deployments can't enforce global limits accurately.

**Solution:**
- Two-tier approach:
  - **Local tier** (fast path): Each node gets 1/N of global budget, atomic token bucket (~100ns)
  - **Global tier** (slow path): Redis-backed shared counters, reconcile every 5 seconds
- Algorithm:
  1. Check local bucket (immediate)
  2. If rejected locally, check Redis (1ms latency) for true global view
  3. Background sync: periodically report local usage to Redis, fetch adjusted quotas
- Config: `distributed_rate_limiting.backend = "redis"`, connection string

**Impact:** Accurate global rate limits across clusters

---

## Protocol & API Extensions

### 5. WebSocket Streaming
**Problem:** Long-running queries or real-time audit tails require polling. No push updates.

**Solution:**
- New endpoint: `ws://proxy/api/v1/stream`
- Protocols:
  - `audit`: subscribe to live audit stream
  - `query`: execute long query, stream rows incrementally
  - `metrics`: real-time metric updates (for dashboard)
- Message format: JSON frames with type discriminator
- Authentication: same Bearer token as HTTP

**Impact:** Real-time dashboards and SIEM integration without polling

---

## Advanced / Future Features

### 8. Multi-Database Transactions
Coordinate transactions across multiple databases with 2PC.

### 16. LLM-Powered Features
- AI policy generator (analyze unknown queries, auto-create policies)
- AI anomaly explanation (explain why this behavior is anomalous)
- Natural language to policy (admin types intent, LLM generates TOML)
- SQL intent classification (detect business-logic attacks beyond syntax)

---

## Implementation Priority

**P1 (High Impact):**
- WebSocket streaming (#5)

**P2 (Feature Expansion):**
- Distributed rate limiting (#4)

---

*This roadmap represents a mature, production-ready SQL proxy system with enterprise-grade features.*
