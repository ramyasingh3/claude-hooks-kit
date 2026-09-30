# claude-hooks-kit

Hooks that gate AI / pre-commit diffs: secrets, blocked paths, optional lint/tests.

Exit `0` = allow, `1` = block. Writes an audit line to `.claude-hooks-log.jsonl`.

## Run checks

```bash
python3 tests/test_fixtures.py
python3 hooks/check_ai_diff.py --policy policies/default.json --diff-file tests/fixtures/secret.diff
```

## Hooks

```bash
./hooks/pre_tool_use.sh --diff-file /path/to/change.patch
./hooks/pre_commit.sh          # checks git staged / unstaged diff
```

Policy lives in `policies/default.json`.

## CI

See `.github/workflows/ai-gate.yml`.

## License

MIT
