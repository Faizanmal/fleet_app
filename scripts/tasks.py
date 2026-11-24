"""Cross-platform task entry point used by Makefile and PowerShell instructions."""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("UV_CACHE_DIR", str(ROOT / ".uv-cache"))


def run(*command: str, cwd: Path = ROOT) -> int:
    if os.name == "nt" and command[0] == "pnpm":
        command = (shutil.which("pnpm.cmd") or command[0], *command[1:])
    print("+", " ".join(command), flush=True)
    return subprocess.call(command, cwd=cwd)


def compose_demo(*args: str) -> int:
    return run(
        "docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.demo.yml", *args
    )


def task(name: str) -> int:
    if os.name != "nt" and hasattr(os, "getuid"):
        os.environ.setdefault("HOST_UID", str(os.getuid()))
        os.environ.setdefault("HOST_GID", str(os.getgid()))
    if name == "setup":
        commands = [
            ("uv", "sync", "--group", "dev", "--extra", "observability"),
            ("pnpm", "--dir", "apps/web", "install", "--frozen-lockfile"),
        ]
        for command in commands:
            result = run(*command)
            if result:
                return result
        env_path = ROOT / ".env"
        if not env_path.exists():
            template = (ROOT / ".env.example").read_text(encoding="utf-8")
            env_path.write_text(template, encoding="utf-8")
        return 0
    if name == "up":
        result = task("migrate")
        if result:
            return result
        return run("docker", "compose", "up", "-d", "--build")
    if name == "down":
        return run("docker", "compose", "down")
    if name == "demo-up":
        env_path = ROOT / ".env"
        if not env_path.exists():
            env_path.write_text(
                (ROOT / ".env.example").read_text(encoding="utf-8"), encoding="utf-8"
            )
            print("Created .env from the disposable local template.", flush=True)
        source = ROOT / "data" / "device-telemetry-dataset.ndjson"
        if not source.is_file():
            print(
                "Pinned demo dataset missing: data/device-telemetry-dataset.ndjson", file=sys.stderr
            )
            return 2
        result = compose_demo("up", "-d", "db")
        if result:
            return result
        result = task("seed")
        if result:
            return result
        result = compose_demo("up", "-d", "--build", "--wait")
        if result:
            return result
        print("\nRayda historical demo is ready:", flush=True)
        print("  Web: http://localhost:3000", flush=True)
        print("  API readiness: http://localhost:8000/api/v1/ready", flush=True)
        print(
            "  Identity fixtures: UI selectors cover Acme / Globex / Initech; "
            "viewer/operator/approver roles.",
            flush=True,
        )
        print(
            "  API fixture bearer format: demo-<tenant-key>-<role> (Acme admin: demo-acme-admin).",
            flush=True,
        )
        print(
            "  Proposal review: requester/approver role separation; actions remain simulated.",
            flush=True,
        )
        print("  Dataset import report: reports/ingest.json", flush=True)
        return 0
    if name == "demo-down":
        return compose_demo("stop")
    if name == "demo-reset":
        result = compose_demo("down", "--volumes", "--remove-orphans")
        return result if result else task("demo-up")
    if name == "migrate":
        result = run("docker", "compose", "run", "--rm", "role-bootstrap")
        if result:
            return result
        result = run("docker", "compose", "build", "migrator")
        if result:
            return result
        return run(
            "docker",
            "compose",
            "run",
            "--rm",
            "migrator",
            "alembic",
            "-c",
            "apps/api/alembic.ini",
            "upgrade",
            "head",
        )
    if name == "ingest":
        source = ROOT / "data" / "device-telemetry-dataset.ndjson"
        if not source.exists():
            print("Dataset missing: expected data/device-telemetry-dataset.ndjson", file=sys.stderr)
            return 2
        result = task("migrate")
        if result:
            return result
        reports = ROOT / "reports"
        reports.mkdir(exist_ok=True)
        return run(
            "docker",
            "compose",
            "run",
            "--rm",
            "ingest-runner",
            "python",
            "-m",
            "fleet.ingest.cli",
            "import",
            "/app/data/device-telemetry-dataset.ndjson",
            "--json-report",
            "/app/reports/ingest.json",
        )
    if name == "seed":
        return task("ingest")
    if name == "test":
        result = run("uv", "run", "pytest")
        if result:
            return result
        result = task("migrate")
        if result:
            return result
        return run("docker", "compose", "run", "--build", "--rm", "test-runner")
    if name == "lint":
        result = run(
            "uv",
            "run",
            "ruff",
            "check",
            "--no-cache",
            "apps/api/src",
            "apps/api/tests",
            "apps/api/migrations",
            "scripts",
        )
        if result:
            return result
        result = run("pnpm", "--dir", "apps/web", "lint")
        if result:
            return result
        return run("pnpm", "--dir", "apps/web", "exec", "tsc", "--noEmit")
    if name == "eval-offline":
        return run("uv", "run", "--no-sync", "python", "scripts/eval_harness.py", "offline")
    if name == "eval-security":
        result = run("uv", "run", "--no-sync", "python", "scripts/security_chaos.py")
        if result:
            return result
        return run("uv", "run", "--no-sync", "python", "scripts/eval_harness.py", "security")
    if name == "eval-live":
        return run("uv", "run", "--no-sync", "python", "scripts/eval_harness.py", "live")
    if name == "action-demo":
        return run("uv", "run", "--no-sync", "python", "scripts/generate_action_demo.py")
    if name == "api-types":
        return run(sys.executable, "scripts/generate_openapi_types.py")
    if name == "check":
        for subtask in ("lint", "test"):
            result = task(subtask)
            if result:
                return result
        return 0
    print(f"Unknown task: {name}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "task",
        choices=[
            "setup",
            "up",
            "down",
            "demo-up",
            "demo-down",
            "demo-reset",
            "migrate",
            "ingest",
            "seed",
            "test",
            "lint",
            "eval-offline",
            "eval-security",
            "eval-live",
            "action-demo",
            "api-types",
            "check",
        ],
    )
    sys.exit(task(parser.parse_args().task))
