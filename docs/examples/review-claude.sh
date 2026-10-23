#!/usr/bin/env bash
# Example hangover `command` runner; requires an authenticated delegate CLI on PATH.
# Claude Opus (high) via delegate safe mode, schema embedded in the prompt.
# Usage: review-claude.sh <prompt-file> <output-json> <schema-file> <repo-dir>
set -euo pipefail
prompt="${1:?prompt}"; out="${2:?output}"; schema="${3:?schema}"; repo="${4:?repo}"
tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
{
  cat "$prompt"
  printf '\n\n## Output contract (binding)\nReturn ONLY one JSON object, no prose, no code fences, matching this JSON Schema exactly (ignore its $schema key):\n'
  cat "$schema"
} > "$tmp/prompt.md"
if ! delegate --json --cwd "$repo" claude safe --model opus --reasoning-effort high --prompt-file "$tmp/prompt.md" > "$tmp/envelope.json" 2> "$tmp/stderr.txt"; then
  cat "$tmp/stderr.txt" >&2
  exit 1
fi
python3 -I - "$tmp/envelope.json" "$out" "$tmp/stderr.txt" "$tool_root/src" <<'PY'
import json, sys
env_path, out_path, err_path, source = sys.argv[1:5]
sys.path.insert(0, source)
from hangover.oracles import parse_delegate_review

try:
    env = json.load(open(env_path))
except Exception as e:
    sys.stderr.write(f"review-claude: envelope unreadable: {e}\n" + open(err_path).read()[-2000:]); sys.exit(1)
if (not isinstance(env, dict) or type(env.get("exitCode")) is not int
        or env["exitCode"] != 0 or env.get("assistantTextTruncated") is True):
    sys.stderr.write("review-claude: failed or truncated delegate evidence\n"); sys.exit(1)
text = env.get("assistantText") or ""
if not text:
    sys.stderr.write("review-claude: empty assistantText; error=%s\n" % env.get("error")); sys.exit(1)
# Accept either review mode here; hangover enforces the requested mode on import.
try:
    obj = parse_delegate_review(text, "initial")
except RuntimeError:
    obj = parse_delegate_review(text, "post_fix")
json.dump(obj, open(out_path, "w"), indent=2)
print("review-claude: wrote", out_path, "verdict=", obj.get("verdict"))
PY
