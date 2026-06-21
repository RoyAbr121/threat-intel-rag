## Phase 1 — Ingestion & Indexing

- Alembic autogenerate compares ALL tables in the target database against your models. If another tool (Langfuse, in our case) shares the same Postgres database, its tables appear as "to be dropped." Fix: add an `include_object` guard in `env.py` to skip tables not in our metadata, and give each service its own database.

- `docker compose restart` does NOT reload environment variables from compose.yaml — it restarts the container with the same config. Use `docker compose up -d --force-recreate` to pick up config changes.

- NVD API CVSS scores are nested inside a `cvssData` sub-object, not at the top level of the metric entry. Autogenerate your Pydantic models from a real API response, not from documentation alone.

- `func.now` (SQLAlchemy) is a factory object. `func.now()` is the SQL expression. `server_default` requires the expression — passing the factory silently fails at runtime, not at definition time.

- `Mapped[DateTime]` vs `Mapped[datetime]`: the type inside `Mapped[]` is the Python type you get at runtime, not the SQLAlchemy column type. Always use Python's `datetime.datetime` inside `Mapped[]`.

- `uv sync --dev` installs `[dependency-groups]` (PEP 735). `uv sync --extra dev` installs `[project.optional-dependencies]`. They are different sections. Prefer `[dependency-groups]` for dev tools so `--dev` works as expected.

- Pre-commit hooks receive explicit file lists from pre-commit, which bypasses ruff's `exclude` config in pyproject.toml. Fix: add `exclude: ^alembic/versions/` directly to the hook config in `.pre-commit-config.yaml`.

- `struct.unpack(">Q", digest[:8])[0]` converts the first 8 bytes of a SHA-256 digest to a uint64. Used to map string CVE IDs to Qdrant's integer point IDs deterministically.

## Phase 0 — Foundations

- Qdrant's official Docker image ships with no HTTP tools (no curl, no wget). Healthcheck falls back to bash `/dev/tcp` — a TCP-level port check rather than HTTP. Trade-off: we verify the port is open, not that the HTTP layer is healthy. Good enough for dev; production would use a sidecar with curl.
    
- `pydantic-settings` reads config in priority order: env vars > .env file > field defaults. Same code works locally and in Docker — no code changes between environments.