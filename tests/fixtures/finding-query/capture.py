"""Regenerate real Fallow 3.31 query outputs, restoring the sample afterward."""
import json
import subprocess
import sys
from pathlib import Path

base = Path(__file__).parent
root = (base / "project").resolve()
binary = sys.argv[1]
args = [binary, "--root", str(root), "dead-code", "--no-type-aware", "--format", "json", "--quiet"]


def run(extra):
    result = subprocess.run(args + extra, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr)
    return json.loads(result.stdout)


identifier = run([])["unused_files"][0]["finding_id"]
query = ["--finding-id", identifier]
found = run(query)
inconclusive = run(query + ["--file", "src/index.js"])
dead = root / "src/dead.js"
content = dead.read_bytes()
try:
    dead.unlink()
    missing = run(query)
    production = run(query + ["--production"])
    entry_exports = run(query + ["--include-entry-exports"])
finally:
    dead.write_bytes(content)
for name, data in (("found", found), ("missing", missing), ("inconclusive", inconclusive),
                   ("production", production), ("entry-exports", entry_exports)):
    (base / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n")
