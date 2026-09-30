#!/usr/bin/env bash
# pre-commit style wrapper
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$ROOT/hooks/check_ai_diff.py" --policy "$ROOT/policies/default.json" --repo .
