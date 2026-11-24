"""Exercise a freshly imported local demo over its public HTTP API."""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
API = "http://127.0.0.1:8000"
TENANT = "acme-001"
STATE = ROOT / "reports" / "demo_smoke_state.json"
REPLAY_FIELDS = (
    "transcript_valid",
    "tool_facts_deterministic",
    "tool_count",
    "tool_facts_sha256",
    "dataset_version_sha256",
    "source_dataset_versions_sha256",
    "policy_version",
    "graph_version",
    "model_version",
)


def call(path: str, *, token: str, method: str = "GET", body: dict | None = None) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Active-Tenant": TENANT,
        "Accept": "application/json",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    if method == "POST":
        headers["Idempotency-Key"] = str(uuid.uuid4())
    request = Request(
        f"{API}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=60) as response:
            return json.loads(response.read())
    except (HTTPError, URLError, TimeoutError) as error:
        raise RuntimeError(f"demo API probe failed: {type(error).__name__}") from None


def before_restart() -> None:
    result = call(
        "/api/v1/agent/runs",
        token="demo-acme-001-viewer",
        method="POST",
        body={"question": "Which devices have less than 20% disk free?"},
    )
    trace_id = result.get("trace_id") or result.get("run_id")
    claims = (result.get("answer") or {}).get("claims", [])
    cited = any(claim.get("evidence_ids") or claim.get("manifest_ids") for claim in claims)
    if not trace_id or not result.get("trace_persisted") or not cited:
        raise RuntimeError("canonical question did not return persisted citation-backed evidence")

    inventory = call(
        "/api/v1/devices?disk_free_percent_below=20&page_size=1",
        token="demo-acme-001-operator",
    )
    items = inventory.get("items", [])
    manifests = inventory.get("manifest_ids", [])
    if not items or not manifests:
        raise RuntimeError("pinned source did not provide a low-disk target and evidence manifest")
    proposal = call(
        "/api/v1/actions/proposals",
        token="demo-acme-001-operator",
        method="POST",
        body={
            "action_kind": "create_upgrade_order",
            "target_id": items[0]["device_id"],
            "payload": {"component": "memory", "spec": "Add 16 GB memory module"},
            "evidence_manifest_ids": [manifests[0]],
            "mode": "SANDBOX_SIMULATION",
        },
    )
    if proposal.get("status") != "PENDING_APPROVAL":
        raise RuntimeError("demo action proposal was not safely queued for human review")
    decision = call(
        f"/api/v1/actions/proposals/{proposal['proposal_id']}/decision",
        token="demo-acme-001-approver",
        method="POST",
        body={"decision": "approve", "proposal_hash": proposal["proposal_hash"]},
    )
    if decision.get("status") != "APPROVED":
        raise RuntimeError("separate approver did not approve the simulated proposal")
    execution = call(
        f"/api/v1/actions/proposals/{proposal['proposal_id']}/execute",
        token="demo-acme-001-operator",
        method="POST",
        body={"proposal_hash": proposal["proposal_hash"]},
    )
    if (
        execution.get("status") != "EXECUTED"
        or execution.get("simulation_mode") != "SANDBOX_SIMULATION"
        or execution.get("result", {}).get("simulated") is not True
    ):
        raise RuntimeError("approved proposal did not produce its sandbox-only simulated result")

    STATE.parent.mkdir(exist_ok=True)
    STATE.write_text(
        json.dumps(
            {
                "tenant": TENANT,
                "trace_id": trace_id,
                "proposal_id": proposal["proposal_id"],
                "proposal_status": decision["status"],
                "execution_id": execution["execution_id"],
                "execution_status": execution["status"],
                "mode": proposal.get("proposal", {}).get("mode", "SANDBOX_SIMULATION"),
                "external_actions_performed": False,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        "question=passed citations=present trace=persisted "
        "proposal=approved sandbox_execution=recorded"
    )


def after_restart() -> None:
    if not STATE.is_file():
        raise RuntimeError("missing pre-restart demo trace state")
    state = json.loads(STATE.read_text(encoding="utf-8"))
    trace_id = state["trace_id"]
    stored = call(f"/api/v1/agent/runs/{trace_id}", token="demo-acme-001-viewer")
    if stored.get("trace_id") != trace_id or not stored.get("step_events"):
        raise RuntimeError("database-backed run trace was unavailable after restart")
    proposal = call(
        f"/api/v1/actions/proposals/{state['proposal_id']}", token="demo-acme-001-operator"
    )
    execution = proposal.get("execution") or {}
    if (
        proposal.get("status") != "EXECUTED"
        or execution.get("execution_id") != state["execution_id"]
        or execution.get("result", {}).get("simulated") is not True
    ):
        raise RuntimeError("sandbox execution ledger was not preserved after API restart")
    first = call(f"/api/v1/agent/runs/{trace_id}/replay", token="demo-acme-001-viewer")
    second = call(f"/api/v1/agent/runs/{trace_id}/replay", token="demo-acme-001-viewer")
    if not all(first.get(field) == second.get(field) for field in REPLAY_FIELDS):
        raise RuntimeError("deterministic replay projection changed between repeated calls")
    if not first.get("transcript_valid") or not first.get("tool_facts_deterministic"):
        raise RuntimeError("persisted replay transcript did not verify")
    print(
        "restart=passed persisted_trace=present sandbox_execution=persisted "
        "replay_twice=deterministic"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"before-restart", "after-restart"}:
        raise SystemExit("usage: python scripts/demo_smoke.py before-restart|after-restart")
    (before_restart if sys.argv[1] == "before-restart" else after_restart)()
