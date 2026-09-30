#!/usr/bin/env python3
"""Fixture checks for hook policy behavior."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "hooks" / "check_ai_diff.py"
POLICY = ROOT / "policies" / "default.json"
FIX = ROOT / "tests" / "fixtures"


def run(diff: Path) -> int:
    p = subprocess.run(
        [sys.executable, str(CHECK), "--policy", str(POLICY), "--diff-file", str(diff)],
        capture_output=True,
        text=True,
    )
    return p.returncode


def main() -> int:
    assert run(FIX / "clean.diff") == 0, "clean.diff should pass"
    assert run(FIX / "secret.diff") == 1, "secret.diff should block"
    assert run(FIX / "blocked_path.diff") == 1, "blocked_path.diff should block"
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
