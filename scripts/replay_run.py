"""Call the authenticated deterministic tool-fact replay twice and compare exactly."""

from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

COMPARE = (
    "transcript_valid",
    "tool_facts_deterministic",
    "tool_count",
    "tool_facts_sha256",
    "tool_facts",
    "dataset_version_sha256",
    "source_dataset_versions_sha256",
    "policy_version",
    "graph_version",
    "model_version",
)


def get_replay(base: str, run_id: str, tenant: str, token: str) -> dict:
    request = Request(
        f"{base}/api/v1/agent/runs/{run_id}/replay",
        headers={"Authorization": f"Bearer {token}", "X-Active-Tenant": tenant},
    )
    with urlopen(request, timeout=20) as response:
        return json.loads(response.read())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    args = parser.parse_args()
    token = os.getenv("FLEET_BEARER_TOKEN")
    tenant = os.getenv("AUDIT_TENANT_KEY")
    if not token or not tenant:
        print(
            "Set FLEET_BEARER_TOKEN and AUDIT_TENANT_KEY for an authorized tenant session.",
            file=sys.stderr,
        )
        return 2
    base = os.getenv("FLEET_API_URL", "http://127.0.0.1:8000").rstrip("/")
    try:
        first = get_replay(base, args.run_id, tenant, token)
        second = get_replay(base, args.run_id, tenant, token)
    except (HTTPError, URLError, TimeoutError) as exc:
        print(f"Replay request failed ({type(exc).__name__}).", file=sys.stderr)
        return 1
    same = all(first.get(key) == second.get(key) for key in COMPARE)
    report = {
        **first,
        "replay_runs": 2,
        "deterministic_fields_match": same,
        "compared_fields": list(COMPARE),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if same and first.get("transcript_valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())
