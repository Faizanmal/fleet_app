from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "eval_query_oracles", ROOT / "scripts" / "eval_query_oracles.py"
)
assert SPEC is not None and SPEC.loader is not None
ORACLES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLES)


def test_source_query_oracles_exactly_match_frozen_golden():
    expected = json.loads(ORACLES.GOLDEN.read_text(encoding="utf-8"))
    assert ORACLES.compute_oracles() == expected
