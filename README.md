# Rayda Fleet Copilot

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![LangGraph](https://img.shields.io/badge/LangGraph-1.0+-orange.svg)](https://langchain-ai.github.io/langgraph/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.121+-green.svg)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-16.4+-black.svg)](https://nextjs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade, evidence-led **Agentic AI Fleet Copilot** designed for multi-tenant IT asset and fleet management intelligence.

The system enables IT administrators to interact with multi-tenant fleet telemetry data using natural language to answer complex fleet health/compliance questions, detect time-series trends and anomalies, and safely propose operational actions backed by cryptographic evidence and strict human-in-the-loop guardrails.

---

## Table of Contents
1. [Overview & Pinned Dataset](#1-overview--pinned-dataset)
2. [Installation and Setup](#2-installation-and-setup)
3. [Running the Agent](#3-running-the-agent)
4. [Running Evaluations](#4-running-evaluations)
5. [Agent Architecture](#5-agent-architecture)
6. [Tool Catalog](#6-tool-catalog)
7. [Grounding Strategy & Evidence Ledger](#7-grounding-strategy--evidence-ledger)
8. [Guardrails & Safety Controls](#8-guardrails--safety-controls)
9. [Key Design Decisions & Trade-Offs](#9-key-design-decisions--trade-offs)

---

## 1. Overview & Pinned Dataset

The platform ingests and operates on historical point-in-time device telemetry:
* **Companies (Tenants):** 3 (`acme-001`, `globex-002`, `initech-003`)
* **Managed Devices:** 25 devices (Acme: 10, Globex: 8, Initech: 7)
* **Snapshot Observations:** ~750 snapshots (30 observations per device over 30 days)
* **Source Dataset:** `data/device-telemetry-dataset.ndjson`
* **Dataset SHA-256:** `fb0ee31ffeeb731b919fc4d5124098c9c5b68cf3fba35eed5092a9f73655c4de`

Importing validates the pinned SHA-256 hash idempotently before populating PostgreSQL.

---

## 2. Installation and Setup

### Prerequisites
* **Python 3.12+** and [`uv`](https://docs.astral.sh/uv/) package manager
* **Node.js 20+** and [`pnpm`](https://pnpm.io/)
* **Docker Engine with Compose v2** (for containerized PostgreSQL with forced RLS)
* *Optional:* GNU Make (Windows users can use the Python task runner `python scripts/tasks.py <target>`)

### Quick Setup

```sh
# Clone repository
git clone <repo-url>
cd Rayda_fleet_intelligence

# Configure environment variables
cp .env.example .env

# Install backend dependencies with uv
uv sync

# Install frontend dependencies with pnpm
pnpm --dir apps/web install
```

### Starting the Services (Docker Demo)

```sh
# Start database, run migrations, seed telemetry, and start API & Web UI
make demo-up
# Or on Windows PowerShell:
python scripts/tasks.py demo-up
```

Access the UI at: **<http://localhost:3000>**  
API Documentation (Swagger): **<http://localhost:8000/docs>**

To stop containers:
```sh
make demo-down    # preserves database volume
make demo-reset   # resets database and volumes
```

---

## 3. Running the Agent

### Live LLM vs. Deterministic Offline Mode
The agent automatically configures its planning strategy:
1. **Live LLM Reasoning:** If an API key is provided (`OPENAI_API_KEY` or `GEMINI_API_KEY`) in `.env`, the agent uses `ProviderPlanner` to drive dynamic multi-step tool calling and natural language synthesis.
2. **Deterministic Offline Mode:** If no model key is set, the agent seamlessly uses `FakePlanner`, providing deterministic keyword/oracle dispatch so evaluation suites run with zero cost and 100% repeatability.

### Running via Web Console
Navigate to `http://localhost:3000`:
* Select your active tenant (`Acme`, `Globex`, or `Initech`) and fixture role (`viewer`, `operator`, `approver`).
* Try sample natural language queries in the Copilot:
  * *"Which devices have less than 20% disk free?"*
  * *"Show me laptops failing high-severity compliance checks."*
  * *"How many devices are running an OS older than macOS 15?"*
  * *"What is the exact battery health percentage?"* (Agent demonstrates correct zero-hallucination abstention).
* Inspect the returned evidence cards (`ev_<hash>`) and aggregate manifests (`man_<hash>`).

### Running via HTTP API (cURL)

```sh
curl -X POST http://localhost:8000/api/v1/agent/runs \
  -H "Authorization: Bearer dev-token-acme-viewer" \
  -H "X-Active-Tenant: acme-001" \
  -H "Idempotency-Key: demo-run-key-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Which devices at Acme are low on disk space?"
  }'
```

---

## 4. Running Evaluations

The repository includes a comprehensive, multi-layer evaluation harness:

```sh
# Run offline regression suite (46 deterministic cases + cold re-run)
make eval-offline
# Or: python scripts/tasks.py eval-offline

# Run security chaos probes (41 hostile injection/traversal probes)
make eval-security
# Or: python scripts/tasks.py eval-security

# Run unit and integration tests
make test
# Or: python scripts/tasks.py test

# Run code style, ESLint, and TypeScript validation
make lint
# Or: python scripts/tasks.py lint
```

### Key Verification Metrics
* **Source Oracle Match:** 100% match against frozen dataset oracles:
  * Acme disk free < 20%: Exactly 2 devices (`8NM23J95R5I6` at 2.59% and `MT7PJB7N5LRE` at 2.00%).
  * Devices running macOS older than 15: Exactly 10 devices across tenants (4 Acme, 2 Globex, 4 Initech).
  * High-severity failures in source: Exactly 0.
* **Security Probes:** 41/41 passed (cross-tenant access denied, malicious SQL/shell blocked, telemetry prompt injections treated strictly as untrusted data).

---

## 5. Agent Architecture

The agent is designed around an explicit, inspectable state machine implemented in **LangGraph (`StateGraph`)**. A simple prompt wrapper was deliberately avoided.

```mermaid
flowchart TD
    User([User Question]) --> Session[AgentSession Context Bound]
    Session --> PlanNode[Plan Node: LLM / Structured Planner]
    PlanNode --> Decision{Need Tools?}
    Decision -->|Yes| ToolNode[Tool Execution Node: Closed Gateway]
    ToolNode --> AssessNode[Assessment / Plan Revision Node]
    AssessNode -->|Rounds < 3| PlanNode
    AssessNode -->|Complete or Cap Reached| AnswerNode[Answer Node: Citation & Schema Validation]
    AnswerNode --> Output([Grounded Agent Answer])
```

### Architectural Guarantees
1. **Explicit Agent Loop:** Compiles `plan → tools → assessment → answer` edges. Allows up to 3 iterative planning rounds and a maximum of 12 tool calls.
2. **Strict Schema Constraints:** Planner outputs must validate against the Pydantic `Plan` schema.
3. **Execution Budgets:** Character limits (question: 2,000, answer: 4,000, history: 8,000) and query caps prevent runaway execution or context explosion.
4. **Deterministic Trace Replay:** `replay_run(run_id)` deterministically reprojects sanitized execution transcripts without re-querying external sources.

---

## 6. Tool Catalog

All tools enforce strict Pydantic input models (`extra="forbid"`), automatic whitespace stripping, and tenant scoping from server-verified `RequestContext`.

| Tool Name | Scope | Description & Parameter Bounds |
| :--- | :---: | :--- |
| `list_devices` | Read | Latest-per-device inventory with closed filters (platform, disk %, RAM, OS major), stable paging (1–100/page). |
| `get_device_snapshot` | Read | Retrieves one device snapshot; foreign/missing IDs fail closed with opaque `not_found`. |
| `query_compliance` | Read | Filter compliance checks by `status`, `severity`, or `check_id`. |
| `list_software` | Read | Exact-name lookup for installed applications; results remain untrusted telemetry data. |
| `get_device_history` | Read | Bounded time-series metric observations (up to 366 days, max 500 points). |
| `compute_fleet_trends` | Read | Aggregates metric trends across up to 5,000 observations with configurable coverage threshold. |
| `rank_fleet_insights` | Read | Heuristic engine detecting persistent low storage, RAM constraints, and battery degradation. |
| `resolve_evidence` | Read | Resolves 1–100 unique `ev_<hash>` evidence pointers under the active tenant. |
| `get_policy_thresholds`| Read | Reads configured SLA, warning, and critical thresholds for a given policy version. |
| `get_action_preconditions`| Read | Verifies non-executable prerequisites and evidence validity prior to proposing actions. |

---

## 7. Grounding Strategy & Evidence Ledger

Every factual claim emitted by the Copilot is grounded in immutable telemetry:
* **Evidence Pointers (`ev_<sha256>`):** Point directly to specific tenant-owned telemetry observations and field paths.
* **Aggregate Manifests (`man_<sha256>`):** Capture the query fingerprint, filter criteria, denominator/numerator counts, coverage percentage, source references, and dataset hash.
* **Structured Claim Verifier (`/api/v1/evidence/verify-claim`):** Enables programmatic re-verification of field values, counts, ratios, and percentages directly against stored manifests.
* **Zero-Hallucination Battery Policy:** The dataset records battery charge, full-charge capacity, and cycle count, but **lacks a design capacity specification**. Rather than inferring a fabricated percentage, the agent strictly abstains and explains the evidence gap.

---

## 8. Guardrails & Safety Controls

State-changing actions adhere to zero-trust design principles:

### 1. Multi-Tenant Isolation
* **PostgreSQL Row Level Security:** Enforced at the engine level with `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`.
* **Least-Privilege Database Roles:** The API connects as `fleet_app` (`NOSUPERUSER`, `NOBYPASSRLS`). Tenant scope is injected transaction-locally via `SET LOCAL app.tenant_id`.

### 2. Human-in-the-Loop (HITL) Action Pipeline
* **Separation of Duties:** Proposer cannot approve their own proposal (`requester_id != approver_id`).
* **Canonical Hash Binding:** Approvals and sandbox executions require the exact SHA-256 hash of the proposal payload, preventing concurrent tampering or race conditions.
* **Simulated Sandbox Execution:** State-changing actions execute into a database-backed sandbox ledger; no live external orders, emails, or tickets are dispatched without explicit adapter activation.
* **Minimum Evidence Coverage:** Action proposals require at least 70% verified evidence coverage and are rejected if based on stale telemetry (>7 days).

### 3. Cryptographic Audit Ledger
* High-assurance Merkle-like hash chaining where each audit event cryptographically seals the predecessor's hash (`verify_audit_chain.py`). Any manual tampering is instantly detected.

---

## 9. Key Design Decisions & Trade-Offs

1. **Deterministic Offline Default vs. Live Model Adapter:**  
   * *Decision:* Provided a dual-mode planner (`ProviderPlanner` for live OpenAI/Gemini structured outputs, `FakePlanner` for deterministic keyword dispatch).
   * *Trade-off:* Guarantees that evaluation suites, CI pipelines, and grading benchmarks run with 100% determinism and zero API cost, while allowing live conversational flexibility when keys are supplied.
2. **Separation of Action Tools from Read Tools in the Agent Loop:**  
   * *Decision:* Model-facing gateway tools return `PROPOSAL_NOT_YET_IMPLEMENTED` and are excluded from `READ_TOOL_NAMES`. Proposals are staged as drafts and require explicit human-in-the-loop review.
   * *Trade-off:* Prevents indirect prompt injection attacks from automatically ordering hardware or firing tickets without human authorization.
3. **Primary Disk Selection by Platform:**  
   * *Decision:* Only evaluates primary mount volumes (`/` on macOS/Darwin, `C:\` on Windows) using `ROUND_HALF_UP` decimal arithmetic.
   * *Trade-off:* Eliminates noise from virtual memory mounts, recovery partitions, and temporary storage volumes.

---

## Verification & Quality
* **Dataset SHA-256:** `fb0ee31ffeeb731b919fc4d5124098c9c5b68cf3fba35eed5092a9f73655c4de`
* **Test Suite:** 100% passing across unit, offline eval (46 cases), security chaos (41 probes), linting, and typecheck.
