"""Verify a tenant audit chain through the authenticated API."""

from __future__ import annotations

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main() -> int:
    token = os.getenv("FLEET_BEARER_TOKEN")
    tenant = os.getenv("AUDIT_TENANT_KEY")
    if not token or not tenant:
        print(
            "Set FLEET_BEARER_TOKEN and AUDIT_TENANT_KEY; the API requires an authenticated admin.",
            file=sys.stderr,
        )
        return 2
    base = os.getenv("FLEET_API_URL", "http://127.0.0.1:8000").rstrip("/")
    request = Request(
        f"{base}/api/v1/actions/audit-chain",
        headers={"Authorization": f"Bearer {token}", "X-Active-Tenant": tenant},
    )
    try:
        with urlopen(request, timeout=15) as response:
            report = json.loads(response.read())
    except (HTTPError, URLError, TimeoutError) as exc:
        print(f"Audit verifier request failed ({type(exc).__name__}).", file=sys.stderr)
        return 1
    # Do not echo credentials or the tenant's human-readable key.
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())
