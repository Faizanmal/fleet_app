"""Run deterministic offline/security evaluation suites and emit auditable JSON reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api" / "src"))
REPORTS = ROOT / "reports"
SOURCE = ROOT / "data" / "device-telemetry-dataset.ndjson"
SEED = 40204
OFFLINE_TESTS = [
    "apps/api/tests/test_query_oracles.py",
    "apps/api/tests/test_deterministic_metrics.py",
    "apps/api/tests/test_insights.py",
    "apps/api/tests/test_agent_graph.py",
    "apps/api/tests/test_ingest_schemas.py",
]
SECURITY_TESTS = [
    "apps/api/tests/test_security_chaos.py",
    "apps/api/tests/test_agent_graph.py",
    "apps/api/tests/test_tool_gateway.py",
    "apps/api/tests/test_auth_and_rbac.py",
    "apps/api/tests/test_actions_policy.py",
    "apps/api/tests/test_actions_postgres.py",
    "apps/api/tests/test_evidence_ledger.py",
]


def _git_sha() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _parse_junit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    root = ET.parse(path).getroot()
    cases = []
    for node in root.iter("testcase"):
        failure = node.find("failure")
        error = node.find("error")
        skipped = node.find("skipped")
        outcome = (
            "failed"
            if failure is not None or error is not None
            else ("skipped" if skipped is not None else "passed")
        )
        detail_node = (
            skipped if skipped is not None else (failure if failure is not None else error)
        )
        cases.append(
            {
                "id": f"{node.attrib.get('classname', '')}::{node.attrib.get('name', '')}",
                "name": node.attrib.get("name", "unknown"),
                "outcome": outcome,
                "duration_seconds": float(node.attrib.get("time", "0")),
                "detail": (
                    (detail_node.attrib.get("message") or "")[:250]
                    if outcome == "skipped" and detail_node is not None
                    else None
                ),
            }
        )
    return cases


def _pytest_pass(test_files: list[str]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="fleet-eval-") as temporary:
        xml_path = Path(temporary) / "junit.xml"
        started = time.perf_counter()
        command = [sys.executable, "-m", "pytest", "-q", *test_files, f"--junitxml={xml_path}"]
        proc = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        cases = _parse_junit(xml_path)
        return {
            "command": command,
            "return_code": proc.returncode,
            "duration_ms": elapsed,
            "passed": sum(c["outcome"] == "passed" for c in cases),
            "failed": sum(c["outcome"] == "failed" for c in cases),
            "skipped": sum(c["outcome"] == "skipped" for c in cases),
            "cases": cases,
            "stdout_tail": proc.stdout[-3000:],
            "stderr_tail": proc.stderr[-2000:],
        }


def _select(cases: list[dict[str, Any]], *parts: str) -> list[dict[str, Any]]:
    return [c for c in cases if all(part in c["id"] for part in parts)]


def _rate(cases: list[dict[str, Any]], *, success_when: str = "passed") -> dict[str, Any]:
    executed = [case for case in cases if case["outcome"] != "skipped"]
    numerator = sum(case["outcome"] == success_when for case in executed)
    denominator = len(executed)
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": (numerator / denominator) if denominator else None,
        "skipped": len(cases) - denominator,
        "case_ids": [case["id"] for case in cases],
    }


def _count(cases: list[dict[str, Any]], *, failed_outcome: str = "failed") -> dict[str, Any]:
    executed = [case for case in cases if case["outcome"] != "skipped"]
    return {
        "value": sum(case["outcome"] == failed_outcome for case in executed) if executed else None,
        "denominator": len(executed),
        "skipped": len(cases) - len(executed),
        "case_ids": [case["id"] for case in cases],
        "status": "measured" if executed else "unavailable",
    }


def _oracle_case() -> dict[str, Any]:
    try:
        spec = __import__("importlib.util", fromlist=["spec_from_file_location"])
        module_spec = spec.spec_from_file_location(
            "offline_oracles", ROOT / "scripts/eval_query_oracles.py"
        )
        module = spec.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        actual = module.compute_oracles()
        expected = json.loads(module.GOLDEN.read_text(encoding="utf-8"))
        passed = actual == expected
        expected_devices = {"8NM23J95R5I6", "MT7PJB7N5LRE"}
        observed_devices = {
            item["device_id"] for item in actual["acme_primary_disk_free_below_20_percent"]
        }
        return {
            "id": "fixed_source_oracles",
            "outcome": "passed" if passed else "failed",
            "expected_device_ids": sorted(expected_devices),
            "actual_device_ids": sorted(observed_devices),
            "zero_high_severity_failures": actual[
                "latest_high_severity_compliance_failures_all_tenants"
            ]
            == 0,
            "data_sha256": actual["data_sha256"],
            "detail": (
                None if passed else "Recomputed frozen source oracle differs from golden JSON."
            ),
        }
    except Exception as exc:  # report errors without hiding their failed status
        return {"id": "fixed_source_oracles", "outcome": "failed", "detail": type(exc).__name__}


def _metric(cases: list[dict[str, Any]], *, absent_reason: str | None = None) -> dict[str, Any]:
    result = _rate(cases)
    if result["denominator"] == 0 and absent_reason:
        result["status"] = "unavailable"
        result["reason"] = absent_reason
    else:
        result["status"] = "measured"
    return result


def _metrics(mode: str, suite: dict[str, Any], oracle: dict[str, Any] | None) -> dict[str, Any]:
    cases = suite["cases"]
    metric: dict[str, Any] = {
        "exact_answer_match": _metric(
            _select(cases, "test_actual_graph_invoke_"),
            absent_reason="Graph oracle scenarios were not collected.",
        ),
        "device_id_set_match": {
            "numerator": int(
                bool(
                    oracle
                    and oracle["outcome"] == "passed"
                    and oracle.get("actual_device_ids") == oracle.get("expected_device_ids")
                )
            ),
            "denominator": 1 if oracle else 0,
            "value": (
                1.0
                if oracle
                and oracle["outcome"] == "passed"
                and oracle.get("actual_device_ids") == oracle.get("expected_device_ids")
                else (0.0 if oracle else None)
            ),
            "case_ids": [oracle["id"]] if oracle else [],
        },
        "source_citation_resolvability": {
            "numerator": 0,
            "denominator": 0,
            "value": None,
            "status": "unavailable",
            "reason": (
                "Actual evidence pointer resolution requires imported PostgreSQL data; fixture "
                "citation validation is not counted as source resolvability."
            ),
            "case_ids": [],
        },
        "claim_support_precision": _metric(
            _select(cases, "test_actual_graph_invoke_")
            + _select(cases, "test_hallucinated_evidence_is_rejected"),
            absent_reason="Grounding graph cases were not collected.",
        ),
        "unknown_correctness": _metric(
            _select(cases, "test_battery_health_abstains_without_tool_or_numerical_claim")
            + _select(cases, "test_insufficient_series_is_reported_not_converted_to_normal")
            + _select(cases, "test_actual_graph_invoke_zero_high_fail_with_coverage_caveat"),
            absent_reason="Unknown-state cases were not collected.",
        ),
        "appropriate_abstention": _metric(
            _select(cases, "test_battery_health_abstains_without_tool_or_numerical_claim")
            + _select(cases, "test_hallucinated_evidence_is_rejected"),
            absent_reason="Abstention cases were not collected.",
        ),
        "tenant_leak_count": _count(
            _select(cases, "test_foreign_identifier_is_opaque_not_found")
            + _select(cases, "test_request_context_rejects_unverified_tenant")
            + _select(
                cases, "test_malformed_planner_tenant_injection_and_arbitrary_tools_recover_safely"
            )
            + _select(cases, "test_hostname_prompt_injection_is_data_and_user_cannot_claim_admin")
            + _select(cases, "test_api_ignores_tenant_claims_and_returns_opaque_foreign_not_found")
            + _select(cases, "test_foreign_tenant_proposal_is_opaque_not_found")
            + _select(
                cases,
                "test_run_thread_trace_evidence_proposal_approval_execution_audit_and_snapshot_ids_are_scoped",
            )
        ),
        "unauthorized_action_count": _count(
            _select(
                cases, "test_viewer_role_dependency_denies_write_capability_before_context_creation"
            )
            + _select(cases, "test_viewer_cannot_propose_and_operator_cannot_approve")
            + _select(cases, "test_viewer_cannot_propose_and_proposal_is_stub")
            + _select(cases, "test_transition_capabilities_are_checked_for_active_membership")
        ),
        "duplicate_execution_count": _count(
            _select(cases, "test_restart_approval_resume_execute_retry_and_hash_chain")
        ),
        "tool_budget_violations": _count(
            _select(cases, "test_tool_budget_and_planning_round_limits_stop_without_loops")
            + _select(cases, "test_langgraph_bundle_stops_at_call_budget")
        ),
        "latency_ms": {
            "value": suite["duration_ms"],
            "unit": "milliseconds",
            "denominator": 1,
            "scope": (
                "Entire selected pytest suite wall time, including process startup; "
                "not per-request latency."
            ),
        },
        "provider_tokens": {
            "value": None,
            "denominator": 0,
            "status": "not_applicable",
            "reason": "No genuine provider calls occurred.",
        },
        "provider_cost": {
            "value": None,
            "denominator": 0,
            "status": "not_applicable",
            "reason": "No genuine provider calls occurred.",
        },
    }
    for name in (
        "tenant_leak_count",
        "unauthorized_action_count",
        "duplicate_execution_count",
        "tool_budget_violations",
    ):
        item = metric[name]
        if item.get("denominator") == 0:
            item["status"] = "unavailable"
            continue
        item["gate"] = "pass" if item["value"] == 0 else "fail"
    return metric


def _metadata(data_sha: str | None) -> dict[str, Any]:
    from fleet.agent.graph import MODEL_VERSION

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "git_sha": _git_sha(),
        "data_sha256": data_sha,
        "python_version": platform.python_version(),
        "libraries": {
            name: _version(name)
            for name in ("langgraph", "pydantic", "fastapi", "sqlalchemy", "pytest")
        },
        "policy_versions": {
            "api": os.environ.get("POLICY_VERSION", "policy-v1"),
            "insights": "fleet-policy-v1",
            "actions": "fleet-action-policy-v1",
        },
        "model_version": MODEL_VERSION,
        "seed": SEED,
        "provider_calls": 0,
    }


def write_summary() -> None:
    reports = {}
    for mode in ("offline", "security", "live"):
        path = REPORTS / f"eval_{mode}.json"
        if path.exists():
            reports[mode] = json.loads(path.read_text(encoding="utf-8"))
    lines = [
        "# Evaluation summary",
        "",
        "Generated from the current machine-readable reports.",
        "",
    ]
    for mode, report in reports.items():
        suite = report.get("suite", {})
        lines.extend(
            [
                f"## {mode.title()} evaluation",
                "",
                f"- Status: **{report.get('gate_status', 'unknown')}**",
                f"- Release gate: **{report.get('release_gate_status', 'unknown')}**",
                f"- Git SHA: `{report.get('metadata', {}).get('git_sha') or 'unavailable'}`",
                "- Data SHA-256: "
                f"`{report.get('metadata', {}).get('data_sha256') or 'unavailable'}`",
                f"- Cases: {suite.get('passed', 0)} passed, "
                f"{suite.get('failed', 0)} failed, {suite.get('skipped', 0)} skipped.",
            ]
        )
        for limitation in report.get("limitations", []):
            lines.append(f"- Limitation: {limitation}")
        lines.append("")
    (REPORTS / "EVAL_SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def run_mode(mode: str) -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    if not SOURCE.exists():
        data_sha = None
    else:
        data_sha = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    oracle = _oracle_case() if mode == "offline" else None
    test_files = OFFLINE_TESTS if mode == "offline" else SECURITY_TESTS
    suite = _pytest_pass(test_files)
    cold_rerun = None
    if mode == "offline":
        cold = _pytest_pass(test_files)
        cold_rerun = {
            "passed": suite["return_code"] == 0
            and cold["return_code"] == 0
            and [(c["id"], c["outcome"]) for c in suite["cases"]]
            == [(c["id"], c["outcome"]) for c in cold["cases"]],
            "first_cases": len(suite["cases"]),
            "second_cases": len(cold["cases"]),
            "second_passed": cold["passed"],
            "second_failed": cold["failed"],
            "second_skipped": cold["skipped"],
        }
    metrics = _metrics(mode, suite, oracle)
    integration_skipped = any(
        c["outcome"] == "skipped" and "postgres" in c["id"] for c in suite["cases"]
    )
    failed = (
        suite["return_code"] != 0
        or (oracle is not None and oracle["outcome"] != "passed")
        or (cold_rerun is not None and not cold_rerun["passed"])
    )
    if mode == "offline":
        gate_status = "FAIL" if failed else "PASS"
    else:
        gate_status = "FAIL" if failed or integration_skipped else "PASS"
    stdout_tail = suite.pop("stdout_tail")
    stderr_tail = suite.pop("stderr_tail")
    suite.pop("command", None)
    release_gate_status = "FAIL" if failed or integration_skipped else "PASS"
    report = {
        "schema_version": "fleet-eval-v1",
        "mode": f"{mode}_baseline" if mode != "live" else "live_provider",
        "gate_status": gate_status,
        "release_gate_status": release_gate_status,
        "metadata": _metadata(data_sha),
        "suite": suite,
        "fixed_oracle": oracle,
        "cold_rerun": cold_rerun,
        "metrics": metrics,
        "release_gates": {
            "fixed_oracles": "PASS" if oracle and oracle["outcome"] == "passed" else "NOT_RUN",
            "source_citation_resolvability": "INCOMPLETE",
            "tenant_isolation": (
                "INCOMPLETE"
                if metrics["tenant_leak_count"]["denominator"] == 0
                or metrics["tenant_leak_count"]["skipped"]
                else "PASS"
            ),
            "unauthorized_actions": (
                "INCOMPLETE"
                if metrics["unauthorized_action_count"]["denominator"] == 0
                or metrics["unauthorized_action_count"]["skipped"]
                else "PASS"
            ),
            "duplicate_execution": (
                "INCOMPLETE"
                if metrics["duplicate_execution_count"]["denominator"] == 0
                or metrics["duplicate_execution_count"]["skipped"]
                else "PASS"
            ),
        },
        "limitations": [],
    }
    if mode == "offline":
        report["limitations"].extend(
            [
                "Evidence pointer source resolvability and durable action execution require "
                "PostgreSQL and are not inferred from in-memory fixture citations.",
                "Latency is whole-suite wall time; provider token and cost metrics are not "
                "applicable because no provider was called.",
            ]
        )
    else:
        report["limitations"].append(
            "PostgreSQL RLS, persistent checkpoint, approval expiry/replay, and concurrent "
            "execution tests are skipped when TEST_DATABASE_URL is not configured."
        )
        if integration_skipped:
            report["limitations"].append(
                "Release security gates requiring live tenant isolation or exactly-once "
                "execution remain INCOMPLETE until database integration tests pass."
            )
    output = REPORTS / f"eval_{mode}.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_summary()
    print(
        f"{mode}: {gate_status}; {suite['passed']} passed, {suite['failed']} failed, "
        f"{suite['skipped']} skipped; report={output.relative_to(ROOT)}"
    )
    if stdout_tail:
        print(stdout_tail)
    if stderr_tail:
        print(stderr_tail, file=sys.stderr)
    return (
        1
        if failed or (mode == "security" and integration_skipped)
        else (2 if gate_status == "INCOMPLETE" else 0)
    )


def run_live() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    provider = os.environ.get("MODEL_PROVIDER")
    model_name = os.environ.get("MODEL_NAME")
    key_name = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "google": "GOOGLE_API_KEY",
    }.get(provider or "")
    key_present = bool(key_name and os.environ.get(key_name))
    report = {
        "schema_version": "fleet-eval-v1",
        "mode": "live_provider",
        "gate_status": "SKIPPED",
        "release_gate_status": "INCOMPLETE",
        "metadata": _metadata(
            hashlib.sha256(SOURCE.read_bytes()).hexdigest() if SOURCE.exists() else None
        ),
        "suite": {"passed": 0, "failed": 0, "skipped": 0, "cases": []},
        "metrics": {
            "provider_tokens": {"value": None, "denominator": 0, "status": "not_run"},
            "provider_cost": {"value": None, "denominator": 0, "status": "not_run"},
        },
        "limitations": [
            "No live provider adapter or provider SDK is configured in this repository; "
            "the presence of credentials alone would not make a run valid.",
            "No provider request was made and no token/cost data was fabricated.",
        ],
        "credential_preflight": {
            "provider_configured": bool(provider),
            "model_configured": bool(model_name),
            "matching_key_present": key_present,
        },
    }
    path = REPORTS / "eval_live.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_summary()
    print(f"live: skipped; provider adapter unavailable; report={path.relative_to(ROOT)}")
    return 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("offline", "security", "live"))
    args = parser.parse_args()
    return run_live() if args.mode == "live" else run_mode(args.mode)


if __name__ == "__main__":
    raise SystemExit(main())
