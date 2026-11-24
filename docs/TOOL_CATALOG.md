# Tool catalog and contract boundaries

## Agent-available read tools

`fleet.agent.schemas.READ_TOOL_NAMES` is the only set exposed to the planner. All calls receive a server-created `RequestContext`; tenant identity is not an input parameter. Inputs are Pydantic models with `extra="forbid"`. The gateway authorizes reads, validates arguments, calls fixed SQLAlchemy repository/query functions, and returns typed `QueryResult` data with timestamps, coverage, evidence IDs/manifests, dataset and policy versions, and typed errors.

| Tool | Structured input | Bounds/behavior |
|---|---|---|
| `list_devices` | `filters`, `as_of`, `page`, `page_size` | Latest-per-device; page 1–10,000; page size 1–100; closed `SnapshotFilters`; tenant from context. |
| `get_device_snapshot` | `device_id`, `as_of`, optional `fields` | One tenant-scoped device; field allowlist; foreign/missing ID is opaque not-found. |
| `query_compliance` | `status`, `severity`, `check_id`, `as_of` | Deterministic compliance observations; high fail means exactly source `fail` and `high`. |
| `list_software` | `name`, optional `version_constraint`, `as_of` | Exact/bounded name lookup and simple version comparison; returned name/title remains untrusted telemetry. |
| `get_device_history` | `device_id`, `metric`, `start`, `end`, `resolution` | Metric is disk-free percent or RAM utilization; at most 366 days and 500 points. |
| `compute_fleet_trends` | `metric`, `start`, `end`, `threshold_policy`, `min_coverage` | Bounded to 5,000 observations; minimum coverage defaults to 0.70; unknowns remain explicit. |
| `rank_fleet_insights` | `as_of`, `policy_version` | Deterministic historical heuristics; no model-selected execution or live source. |
| `resolve_evidence` | `evidence_ids` | 1–100 unique `ev_<64 hex>` pointers; resolves under tenant and labels source fields untrusted. |
| `get_policy_thresholds` | `as_of`, `policy_version` | Reads code-configured policy values. |
| `get_action_preconditions` | `action_type`, `target_id` | Tenant-scoped existence check and non-executable prerequisite summary. |

The gateway-wide limits include 8 calls per bundle, trends up to 5,000 observations, compliance/software up to 1,000 rows, history up to 500 points/366 days, and evidence batches up to 100. HTTP device list pages are at most 100. Invalid, unsupported, or tenant-scope arguments fail closed. Fixed query paths use SQLAlchemy expressions; the gateway accepts no SQL, shell, arbitrary URL, Python, or unrestricted tool selector.

`QueryResult` can contain `items`, `total_count`, paging, `as_of`, `data_as_of`, coverage, evidence IDs/pointers, insufficient-data explanations, source hashes, policy/graph/prompt/model versions, optional policy decision, and typed error. Errors include `not_found`, `insufficient_data`, `policy_denied`, `timeout`, `invalid_input`, `stale`, and `unavailable`. Telemetry strings are source content, never instructions.

## Citation and claim boundaries

Evidence IDs are accepted by the graph only when present in authorized tool outputs. Aggregate manifests preserve source references, query fingerprint, filter/cutoff, numerator/denominator, coverage, freshness, and dataset hash. `POST /api/v1/evidence/verify-claim` accepts a structured evidence `Claim`; deterministic verifiers cover `field_value`, `count`, `list_ids`, `ratio`, and `percent` with exact supported methods. It checks tenant, source references, hash, as-of, coverage, policy, and computed value.

The graph answer schema is different: it stores free-form claim text plus evidence/manifest IDs. Its answer node checks that citations are among IDs from the run, but it does not construct/call the structured claim verifier for each sentence. A valid citation may therefore not entail a provider-generated sentence. The current API uses `FakePlanner`, whose answer is a generic row-count template; no provider model is configured. Do not present the graph citation-membership check as semantic claim verification.

## Action interfaces: API versus model tools

The proposal schema accepts four action kinds with closed payload fields:

| Kind | Required payload | Service policy |
|---|---|---|
| `create_upgrade_order` | `component` (`memory`, `storage_capacity`, or `battery`) and `spec` (1–500 chars) | May create a hash-bound proposal if target/evidence/coverage policy passes; storage replacement text is denied. |
| `open_remediation_ticket` | `check_id`, `note` | Denied unless a matching source `fail`/`high` record exists for the scoped target. The pinned source has zero high-severity failures. |
| `flag_device_for_replacement` | `reason` | Always denied by current policy. |
| `notify_employee` | `message` | Employee target must resolve in the tenant; real external mode is disabled. |

`ProposalRequest` also requires a tenant-scoped target and 1–20 unique `man_<64 hex>` evidence manifests. Payload strings reject control characters, URLs, contacts, and private-key patterns. Supported requests enter `PENDING_APPROVAL`; decision requires a separate approver by default and the exact proposal hash. Proposals expire after 24 hours. Action evidence must cover the requested target and meet 70% observed/eligible coverage. Sandbox evidence older than seven days is marked historical; real external mode is always disabled by API settings.

Important implementation distinction: the four same-named gateway action tools return `PROPOSAL_NOT_YET_IMPLEMENTED`. They are not included in `READ_TOOL_NAMES` and cannot be called by the agent. Proposal creation is available through the HTTP service; the web form currently implements upgrade orders. Approval requires a separate approver. After approval, an operator/admin can submit the exact proposal hash to `/api/v1/actions/proposals/{proposal_id}/execute`; the UI requires separate operator confirmation. The executor writes only a deterministic database-backed `SANDBOX_SIMULATION` result. No network sender exists.

## Selected policy thresholds

| Policy | Value | Source |
|---|---:|---|
| Primary disk warning/critical | `<20%` / `<10%` | `InsightPolicy` |
| Persistent low storage | 7 of 10 observations, observed over at least 7 days | `InsightPolicy` |
| Sustained RAM pressure | `>=85%` on 7 of 10 observations; minimum 70% coverage | `InsightPolicy` |
| Stale observation detector | 7 days | `InsightPolicy.telemetry_sla` |
| Action minimum coverage | 70% observed/eligible | `evaluate_proposal_policy` |
| Proposal expiration | 24 hours | `PROPOSAL_TTL` |
| Real external evidence age | 7 days maximum, but adapter stays disabled | `MAX_EVIDENCE_AGE` |

These are versioned deterministic heuristics, not independently validated fleet recommendations. Definitions and limitations are in `docs/ARCHITECTURE.md` and `docs/DATA_DICTIONARY.md`.

## Code and tests

- Gateway schemas, catalog, dispatch, and budgets: `apps/api/src/fleet/tools/gateway.py`.
- Agent read allowlist and plan contract: `apps/api/src/fleet/agent/schemas.py`.
- Action schemas and policy/state machine: `apps/api/src/fleet/actions/schemas.py`, `apps/api/src/fleet/actions/service.py`.
- Evidence verifier: `apps/api/src/fleet/evidence/ledger.py`.
- Malformed/injection/paging tests: `apps/api/tests/test_tool_gateway.py`, `apps/api/tests/test_security_chaos.py`, `apps/api/tests/test_agent_graph.py`.
