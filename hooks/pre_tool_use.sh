#!/usr/bin/env bash
# Claude Code / shell PreToolUse-style hook entrypoint.
# Usage: ./hooks/pre_tool_use.sh [--diff-file PATH]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$ROOT/hooks/check_ai_diff.py" --policy "$ROOT/policies/default.json" "$@"
