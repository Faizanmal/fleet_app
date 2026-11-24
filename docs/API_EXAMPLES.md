# API examples

Examples use the development fixture auth. It is disabled by default and must
never be enabled in production. Replace tenant/device/evidence identifiers with
values returned for the authenticated tenant. Do not put employee message text,
credentials, or secrets in URLs or logs.

## Health

```sh
curl -sS http://localhost:8000/api/v1/health
```

Observed local handler response (uptime is process-relative):

```json
{"status":"ok","uptime_seconds":0.043,"build_version":"dev"}
```

This is a liveness response. It does not assert PostgreSQL readiness.

## Caller and tenant membership

```sh
curl -sS http://localhost:8000/api/v1/me \
  -H 'Authorization: Bearer demo-acme-001-viewer' \
  -H 'X-Active-Tenant: acme-001'
```

The tenant header can only select a membership already present in the verified
principal. It does not create or grant access to a tenant.

## Low disk inventory

```sh
curl -sS 'http://localhost:8000/api/v1/devices?disk_free_percent_below=20&page=1&page_size=100&as_of=2026-06-12T11%3A00%3A00Z' \
  -H 'Authorization: Bearer demo-acme-001-viewer' \
  -H 'X-Active-Tenant: acme-001'
```

Source-audited values for that tenant/cutoff contain two devices. This excerpt
is not a captured HTTP response; the live envelope also contains fields such as
platform/model, evidence IDs, and the database-persisted manifest ID.

```json
{
  "items": [
    {"device_id":"8NM23J95R5I6","disk_free_percent":"2.59","collected_at":"2026-06-12T09:02:00Z"},
    {"device_id":"MT7PJB7N5LRE","disk_free_percent":"2.00","collected_at":"2026-06-12T08:39:00Z"}
  ],
  "total_count": 2,
  "page": 1,
  "page_size": 100,
  "coverage": {"eligible":10,"observed":10,"unknown":0,"fraction":1.0},
  "data_as_of":"2026-06-12T11:00:00Z",
  "limitations":["Latest observation per device at or before as_of; missing metrics remain unknown."],
  "data_sha256":["fb0ee31ffeeb731b919fc4d5124098c9c5b68cf3fba35eed5092a9f73655c4de"]
}
```

The DB-backed API adds a real `manifest_id` and resolvable `evidence_ids` to
this envelope after import. They are deliberately not invented in this
source-only example. Full exact HTTP responses for evidence resolution require a
PostgreSQL import and are not available in this environment.

## Compliance with observed coverage

```sh
curl -sS 'http://localhost:8000/api/v1/compliance?status=fail&severity=high&as_of=2026-06-12T11%3A00%3A00Z' \
  -H 'Authorization: Bearer demo-acme-001-viewer'
```

The frozen source oracle reports zero high severity failures across observed
records. A live response additionally carries the tenant's manifest ID, source
hash, `data_as_of`, and `coverage`; absent checks remain unknown rather than pass.

## Submit and poll an agent run

```sh
curl -sS -X POST http://localhost:8000/api/v1/agent/runs \
  -H 'Authorization: Bearer demo-acme-001-viewer' \
  -H 'X-Active-Tenant: acme-001' \
  -H 'Idempotency-Key: acme-low-disk-20260612-001' \
  -H 'Content-Type: application/json' \
  -d '{"question":"Which Acme devices have low disk under 20%?"}'
```

The run is synchronous and returns a typed answer, claims, evidence citations,
sanitized operation trace, coverage, and version metadata. Reusing the same
principal/key returns 409 rather than creating a second run. Poll the returned
`run_id` at `/api/v1/agent/runs/{run_id}`; `/events` is JSON polling, not SSE.

## Create and decide an immutable proposal

```sh
curl -sS -X POST http://localhost:8000/api/v1/actions/proposals \
  -H 'Authorization: Bearer demo-acme-001-operator' \
  -H 'X-Active-Tenant: acme-001' \
  -H 'Idempotency-Key: acme-upgrade-20260612-001' \
  -H 'Content-Type: application/json' \
  -d '{"action_kind":"create_upgrade_order","target_id":"<device-id>","payload":{"component":"memory","spec":"Add 16 GB memory module"},"evidence_manifest_ids":["<tenant manifest ID>"],"mode":"SANDBOX_SIMULATION"}'
```

Copy the returned immutable `proposal_hash`, inspect the proposal and its audit,
then approve or reject with the distinct approver identity:

```sh
curl -sS -X POST http://localhost:8000/api/v1/actions/proposals/<proposal-id>/decision \
  -H 'Authorization: Bearer demo-acme-001-approver' \
  -H 'X-Active-Tenant: acme-001' \
  -H 'Content-Type: application/json' \
  -d '{"decision":"approve","proposal_hash":"<64 lowercase hex characters>"}'
```

Approval is not execution. The browser API has no executor route.

## Standard errors

Unauthenticated request (exact response shape):

```json
{"error":{"code":"unauthorized","message":"Unauthorized","trace_id":"<server-generated-opaque-id>"}}
```

Foreign tenant device/evidence/run/proposal IDs use the same opaque 404 message:

```json
{"error":{"code":"not_found","message":"Not found","trace_id":"<server-generated-opaque-id>"}}
```

Run `python scripts/tasks.py migrate`, `python scripts/tasks.py ingest`, and
`python scripts/tasks.py test` with Docker/PostgreSQL available to capture
database-backed responses with persisted citation IDs. Those live response
captures have not been generated in the current environment.
