# Database schema

The phase 01 bootstrap SQL creates the `schema_migrations` bootstrap marker. Alembic now owns application schema evolution; configuration is at `apps/api/alembic.ini` and revision files are in `apps/api/migrations/versions`.

Revision `20261121_01` creates `tenant`, `employee`, `device`, `telemetry_snapshot`, `disk_volume`, `compliance_result`, `installed_software`, and `dataset_import`. Composite keys and foreign keys carry `tenant_id` through snapshots and child facts. Snapshots have a unique `(tenant_id, device_id, collected_at)` key, offset-aware UTC timestamps, source row and dataset hashes, line numbers, raw JSON, and optional battery/network JSON. Byte constraints reject nonpositive volume size and available space outside `[0, size_bytes]`.

Revision `20261121_02` adds tenant-keyed graph-run, evidence, proposal, approval, action-execution, and audit envelopes. It enables and forces RLS on all current tenant-owned tables. See `docs/THREAT_REVIEW.md` for role separation, policy predicates, and database-owner behavior, and `docs/DATA_DICTIONARY.md` for the complete source audit.

Revision `20261122_04` hardens proposals with immutable document hashes and expiry, adds one-time typed approval decisions and versioned idempotent sandbox execution, appends a per-tenant hash-chained audit head, and adds tenant-RLS LangGraph checkpoints and a future-only action outbox. The outbox has no sender. The exact state machine and operational limits are in `docs/ARCHITECTURE.md`.
