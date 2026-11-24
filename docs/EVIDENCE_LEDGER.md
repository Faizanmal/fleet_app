# Evidence ledger

Evidence pointers and aggregate manifests are tenant-owned rows created by `fleet.evidence.ledger`. IDs use SHA-256 over sorted-key, compact UTF-8 canonical JSON. The hash is an integrity identifier, not an authorization token; `tenant_id` predicates and forced RLS control access. A collision with a different stored payload raises an error.

`evidence_pointer` identifies a tenant, dataset hash, database snapshot, device, observation time, exact JSONPath-like field path, and canonical value hash. Capture rejects unrecognized roots and unsupported path syntax. Resolution re-reads the tenant-scoped source snapshot and field and verifies the value hash. Telemetry values are returned as `untrusted_telemetry_data` and must never be treated as instructions.

`aggregate_manifest` stores query type/version, normalized filters and `as_of`, latest-per-device selection rule, matched and excluded source references, numerator/denominator, source hash, query fingerprint, policy threshold version, freshness, and coverage. Manifest inspection pages at most 100 references per request. The query repository persists manifests and stable pointers for source identifiers, timestamps, and OS platform on each aggregate read. Evidence drilldown and claim verification require an authenticated tenant context; unknown or foreign IDs return the same not-found result.

The app role can SELECT and INSERT ledger rows only. Database triggers reject UPDATE and DELETE. RLS is enabled and forced for both tables. The ingest role is privileged only in its isolated batch path. Hashes detect changed values and tampered manifests; the SHA-256 source hash identifies the imported dataset version. This does not preserve original NDJSON whitespace bytes in PostgreSQL, so validation proves referenced field values and dataset identity rather than reconstructing original row bytes from JSONB.

Claims currently verify single-field exact values and count, ID-list, ratio, and percent claims with versioned allowlisted methods. Count claims require complete observed-versus-eligible coverage; a zero high-severity failure count also requires unknown coverage to be zero. Unsupported methods, policy versions, causal claims, missing manifests, foreign evidence, and tampering are rejected. No telemetry language is used as evidence identity or query logic.

Endpoints: `POST /api/v1/evidence/pointers`, `GET /api/v1/evidence/{evidence_id}`, `GET /api/v1/evidence/manifests/{manifest_id}`, and `POST /api/v1/evidence/verify-claim`.

`reports/evidence_example.json` is a source-audited Acme example. PostgreSQL was unavailable during authoring, so its DB-generated snapshot IDs and persisted evidence IDs are explicitly pending rather than fabricated.
