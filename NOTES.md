## Phase 0 — Foundations

- Qdrant's official Docker image ships with no HTTP tools (no curl, no wget). Healthcheck falls back to bash `/dev/tcp` — a TCP-level port check rather than HTTP. Trade-off: we verify the port is open, not that the HTTP layer is healthy. Good enough for dev; production would use a sidecar with curl.
    
- `pydantic-settings` reads config in priority order: env vars > .env file > field defaults. Same code works locally and in Docker — no code changes between environments.