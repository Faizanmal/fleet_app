# Demo Walkthrough and Verification

## Quick Start (Docker)

To run the complete platform locally with PostgreSQL, FastAPI backend, and Next.js frontend:

```sh
# Copy environment configuration
cp .env.example .env

# Launch services via Docker Compose
make demo-up
# Or on Windows without Make:
python scripts/tasks.py demo-up
```

`make demo-up` automatically:
1. Provisions PostgreSQL with isolated roles (`fleet_app`, `fleet_ingest`, and `fleet`).
2. Applies Alembic migrations with forced Row-Level Security (RLS).
3. Verifies and imports the pinned NDJSON dataset idempotently.
4. Boots the FastAPI application and Next.js management console at `http://localhost:3000`.

To stop services:
```sh
make demo-down    # preserves database volume
make demo-reset   # destructive reset of database volumes
```

---

## Interactive Walkthrough

Open `http://localhost:3000` in your browser.

1. **Multi-Tenant Session Switching:**
   * Use the demo header to toggle between fixture identities across tenants:
     * **Acme (`acme-001`):** Viewer, Operator, Approver
     * **Globex (`globex-002`):** Viewer
     * **Initech (`initech-003`):** Viewer
   * Verify that client query caches clear automatically on tenant transition and that cross-tenant access fails closed.

2. **Fleet Copilot Investigations:**
   * Ask: *"Which devices have less than 20% disk free?"*
     * Inspect returned device cards, primary mount disk metrics, and stable evidence pointers (`ev_<hash>`).
   * Ask: *"Show me laptops failing high-severity compliance checks."*
     * Grounded result accurately reflects 0 observed failures from the source dataset.
   * Ask: *"How many devices are running an OS older than macOS 15?"*
     * Inspect returned aggregate count and manifest pointers (`man_<hash>`).
   * Ask: *"What is the exact battery health percentage?"*
     * Observe strict evidence-gap abstention (the dataset records capacity and cycle count, but lacks design capacity).

3. **Human-in-the-Loop Action Workflow:**
   * As an **Operator**, propose an upgrade order for an eligible device under low disk/RAM pressure.
   * Review the staged proposal, canonical SHA-256 hash, and verified evidence coverage.
   * Switch identity to an authorized **Approver** (requester ≠ approver enforced).
   * Approve the proposal, then execute the sandbox simulation as an Operator.
   * Inspect the audit ledger to confirm simulated database state changes without external side-effects.

---

## Automated Browser Testing (E2E)

End-to-end tests for the web console are written with Playwright:

```sh
# Run browser acceptance specs
pnpm --dir apps/web test:e2e
```
