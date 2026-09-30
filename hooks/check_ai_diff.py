#!/usr/bin/env python3
"""Diff policy checks for secrets, blocked paths, and optional lint/tests."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


DEFAULT_POLICY = {
    "block_secrets": True,
    "require_lint": False,
    "require_tests": False,
    "max_changed_lines": 800,
    "blocked_paths": [".env", ".env.*", "**/*credentials*", "**/id_rsa", "**/*.pem"],
    "allowed_secret_examples": ["sk-example", "AKIAEXAMPLE"],
}


SECRET_PATTERNS = [
    (r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}", "api_key_assignment"),
    (r"(?i)secret[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}", "secret_key_assignment"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----", "private_key_pem"),
    (r"sk-[A-Za-z0-9]{20,}", "openai_style_key"),
    (r"sk-ant-[A-Za-z0-9\-_]{20,}", "anthropic_key"),
    (r"ghp_[A-Za-z0-9]{36,}", "github_pat"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "slack_token"),
]


@dataclass
class Finding:
    severity: str
    rule: str
    message: str
    path: str = ""
    line: int = 0


@dataclass
class Report:
    ok: bool = True
    findings: list[Finding] = field(default_factory=list)

    def fail(self, finding: Finding) -> None:
        self.ok = False
        self.findings.append(finding)

    def warn(self, finding: Finding) -> None:
        self.findings.append(finding)


def load_policy(path: Path | None) -> dict:
    policy = dict(DEFAULT_POLICY)
    if path and path.exists():
        data = json.loads(path.read_text())
        policy.update(data)
    return policy


def iter_diff_lines(diff_text: str) -> Iterable[tuple[str, int, str]]:
    """Yield (path, line_no, content) for added lines in a unified diff."""
    path = ""
    new_line = 0
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            continue
        if line.startswith("@@"):
            # @@ -a,b +c,d @@
            m = re.search(r"\+(\d+)", line)
            new_line = int(m.group(1)) if m else 0
            continue
        if line.startswith("+") and not line.startswith("+++"):
            yield path, new_line, line[1:]
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            continue
        else:
            if path:
                new_line += 1


def path_blocked(path: str, patterns: list[str]) -> bool:
    from fnmatch import fnmatch

    base = Path(path).name
    for pat in patterns:
        if fnmatch(path, pat) or fnmatch(base, pat):
            return True
    return False


def is_allowed_example(text: str, allowed: list[str]) -> bool:
    return any(ex in text for ex in allowed)


def check_secrets(diff_text: str, policy: dict, report: Report) -> None:
    if not policy.get("block_secrets", True):
        return
    allowed = policy.get("allowed_secret_examples", [])
    for path, line_no, content in iter_diff_lines(diff_text):
        if is_allowed_example(content, allowed):
            continue
        for pattern, rule in SECRET_PATTERNS:
            if re.search(pattern, content):
                report.fail(
                    Finding(
                        severity="error",
                        rule=rule,
                        message=f"Possible secret in diff: {content.strip()[:80]}",
                        path=path,
                        line=line_no,
                    )
                )


def check_blocked_paths(diff_text: str, policy: dict, report: Report) -> None:
    patterns = policy.get("blocked_paths", [])
    seen = set()
    for path, _, _ in iter_diff_lines(diff_text):
        if path in seen:
            continue
        seen.add(path)
        if path_blocked(path, patterns):
            report.fail(
                Finding(
                    severity="error",
                    rule="blocked_path",
                    message=f"AI edits to blocked path are not allowed: {path}",
                    path=path,
                )
            )


def check_size(diff_text: str, policy: dict, report: Report) -> None:
    max_lines = int(policy.get("max_changed_lines", 800))
    added = sum(1 for _ in iter_diff_lines(diff_text))
    if added > max_lines:
        report.fail(
            Finding(
                severity="error",
                rule="max_changed_lines",
                message=f"Diff adds {added} lines; policy max is {max_lines}",
            )
        )


def run_cmd(cmd: list[str], cwd: Path) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=180)
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out
    except Exception as exc:  # noqa: BLE001
        return 1, str(exc)


def check_lint_tests(repo: Path, policy: dict, report: Report) -> None:
    if policy.get("require_lint"):
        code, out = run_cmd(["python3", "-m", "compileall", "-q", "."], repo)
        if code != 0:
            report.fail(Finding("error", "lint", f"compileall failed:\n{out[:500]}"))
    if policy.get("require_tests"):
        if (repo / "tests").exists() or (repo / "test").exists():
            code, out = run_cmd([sys.executable, "-m", "pytest", "-q"], repo)
            if code != 0:
                report.fail(Finding("error", "tests", f"pytest failed:\n{out[:500]}"))
        else:
            report.warn(Finding("warn", "tests", "require_tests set but no tests/ found"))


def get_diff(repo: Path, diff_file: Path | None) -> str:
    if diff_file:
        return diff_file.read_text()
    code, out = run_cmd(["git", "diff", "--cached"], repo)
    if code != 0:
        return ""
    if out.strip():
        return out
    code, out = run_cmd(["git", "diff"], repo)
    return out if code == 0 else ""


def print_report(report: Report, as_json: bool) -> None:
    if as_json:
        payload = {
            "ok": report.ok,
            "findings": [f.__dict__ for f in report.findings],
        }
        print(json.dumps(payload, indent=2))
        return
    if not report.findings:
        print("claude-hooks-kit: OK — no policy violations")
        return
    for f in report.findings:
        loc = f"{f.path}:{f.line}" if f.path else "-"
        print(f"[{f.severity}] {f.rule} @ {loc}: {f.message}")
    print("claude-hooks-kit: BLOCKED" if not report.ok else "claude-hooks-kit: WARNINGS")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gate AI-generated code changes")
    parser.add_argument("--policy", type=Path, default=Path("policies/default.json"))
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--diff-file", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--log", type=Path, default=Path(".claude-hooks-log.jsonl"))
    args = parser.parse_args(argv)

    policy = load_policy(args.policy if args.policy.exists() else None)
    diff_text = get_diff(args.repo.resolve(), args.diff_file)
    report = Report()

    if not diff_text.strip():
        print("claude-hooks-kit: no diff to check (OK)")
        return 0

    check_blocked_paths(diff_text, policy, report)
    check_secrets(diff_text, policy, report)
    check_size(diff_text, policy, report)
    check_lint_tests(args.repo.resolve(), policy, report)

    entry = {
        "ok": report.ok,
        "findings": [f.__dict__ for f in report.findings],
        "cwd": str(args.repo.resolve()),
    }
    try:
        with args.log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass

    print_report(report, args.json)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
