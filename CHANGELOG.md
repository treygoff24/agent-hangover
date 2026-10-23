# Changelog

## 0.1.1 (2026-10-23)

Removes the last traces of hangover's pre-release name.

- Card IDs now start `hang-` instead of `dslp-`; the hash is unchanged.
  Existing campaigns need the bundled migration utility before use with
  0.1.1. It previews changes, backs up the state and preserves the backlog.
  See [Upgrading an existing campaign](docs/upgrading.md).
- Removed the handling for state left by the pre-release tool: `hangover init --ignore-legacy`, the notice `init` and `doctor` printed about it, and the owner marker's pre-release tool label. hangover reads only `.hangover/`.

## 0.1.0 (2026-10-23)

The first public release.

### What it does

- `hangover run`, `next`, `fix` and `verify` run a behavior-preserving cleanup campaign: discover the repository's own checks, record a baseline, scan with pinned analyzers, review with a fresh-context model, and close a batch only when the gate, the analyzers and the reviewer all pass. State persists in a local `.hangover/` directory.
- `hangover audit --base REF` gates only the debt a change introduces, with an optional fresh review of the whole change (`--require-review`).
- Analyzers: Fallow 3.31.0 for TypeScript and JavaScript; an experimental Rust analysis for Cargo workspaces (clippy, ast-grep 0.50.0, jscpd 5.4.1 and optional cargo-machete). Analyzer findings keep stable identities across line moves, reformatting and analyzer upgrades.
- Review runners: Codex CLI (default), the delegate CLI, a command of your own, or none (prepare the review packet and import the verdict).
- Parallel worktree campaigns: per-branch batches, `hangover packet` for worker lanes, and one gate run for every merged batch (`verify --merged`).
- Every command an agent drives takes `--json`, with a versioned envelope and stable exit codes (0 completed, 1 blocked by a verdict, 2 tool error or security refusal).
- An agent skill, `skills/hangover`, for Claude Code, Codex and other agents that read `SKILL.md` folders.

### Security posture

- Static mode (`--no-checks`) reads an untrusted checkout without running any of its code: no checks, no cargo, no Fallow, git with every repository-configured filter, hook and driver disarmed and a 120-second deadline. It accepts only a regular clone and refuses git configs that include other files. It needs git 2.42 or newer.
- In every mode, a file the repository names is refused (exit 2) when its path is absolute, contains `..`, passes through a symlink, is a hard link or resolves outside the repository. A `.hangover/` the repository tracks is refused, and in static mode an existing `.hangover/` must carry hangover's owner marker.
- See [docs/trust-model.md](docs/trust-model.md) for the full boundary.

### Install

- Installed with npm from GitHub, not the npm registry: `npm install -g --allow-git=root --allow-scripts=@ast-grep/cli git+https://github.com/treygoff24/agent-hangover.git`. The analyzers are exact-pinned runtime dependencies. Requires macOS or Linux, Python 3.11+, Node 22+ and Git.
- The launcher runs the first `python3` on `PATH` in isolated mode (`python3 -I`), so `PYTHONPATH`, the user site directory and the current directory cannot shadow its imports.
