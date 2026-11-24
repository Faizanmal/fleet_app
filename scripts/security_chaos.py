"""Run the deterministic attacker probe suite and require at least 30 executions."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "apps" / "api" / "tests" / "test_security_chaos.py"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="fleet-chaos-") as temporary:
        report = Path(temporary) / "chaos.xml"
        command = [sys.executable, "-m", "pytest", "-q", str(TEST), f"--junitxml={report}"]
        print("$", " ".join(command), flush=True)
        result = subprocess.run(command, cwd=ROOT)
        if not report.exists():
            return result.returncode or 1
        cases = list(ET.parse(report).getroot().iter("testcase"))
        skipped = sum(case.find("skipped") is not None for case in cases)
        failed = sum(
            case.find("failure") is not None or case.find("error") is not None for case in cases
        )
        print(
            f"Chaos probes executed={len(cases)} "
            f"passed={len(cases) - skipped - failed} failed={failed} skipped={skipped}"
        )
        if len(cases) < 30 or skipped or failed:
            print(
                "Security chaos gate failed: require 30+ executed probes and zero failures/skips.",
                file=sys.stderr,
            )
            return 1
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
