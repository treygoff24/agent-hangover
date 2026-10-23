# Contributing to agent-hangover

Instructions for anyone changing this repository, human or coding agent.
`CLAUDE.md` is a link to this file.

## What is here

- `src/hangover/`: the `hangover` CLI, a Python 3.11+ package using only the
  standard library. `PYTHONPATH=src python3 -m hangover` runs it from a checkout.
- `bin/hangover`: the launcher npm installs as both `hangover` and
  `agent-hangover`. It re-runs `python3 -I` and pins its own `src/` first.
- `prompts/` and `schemas/`: the review prompts and the review JSON schema.
- `skills/hangover/`: the agent skill that drives the workflow.
- `docs/`: user documentation. `trust-model.md` is the security boundary,
  `reference.md` the commands and exit codes, `agent-setup.md` the install
  guide for AI agents; `command-review-runner.md` and `docs/examples/` are the
  contract for a custom review command, with one example runner.
- `tests/`: unit and end-to-end tests against disposable Git repositories;
  Rust fixtures live in `tests/fixtures/rust/`.

[docs/trust-model.md](docs/trust-model.md) describes the behaviour every
change must keep, including its safety rules for remediation. Read it before
touching anything that runs a subprocess, reads a repository file, or writes
state.

## Rules that hold

- **Read repository files only through the containment helper.** Any path the
  repository names (gate scripts, `package.json`, `Makefile`, `Cargo.toml`,
  `.hangover-rust.json`, analyzer configs, sources) goes through
  `repository.contained_path` / `open_repo_file` / `read_repo_file`, which
  refuse absolute paths, `..`, symlinks in any component, hard links and
  anything outside the repository with a `RepositoryRefusal` (exit 2). Do not
  add a `read_text`, `open` or `exists()` on a repository path that bypasses it.
- **Git runs disarmed.** Every git call made while inspecting a checkout runs
  in the shared no-execute environment (`repository.no_execute_git` /
  `no_execute_git_env`): hooks, filters, diff and
  merge drivers, fsmonitor, includes, lazy fetches and remote helpers are
  switched off with environment config that outranks the repository's own.
  A new git subcommand or config key that can execute or open a file needs an
  override and a test with a planted repository.
- **`--no-checks` executes nothing the repository controls.** Static mode
  accepts only a regular clone, skips Fallow, refuses tracked or unowned
  `.hangover/` state, and bounds every git call
  (`STATIC_GIT_TIMEOUT_SECONDS`). Executing mode runs the configured gate with
  the user's permissions; say so wherever it matters.
- **State is ours or refused.** `.hangover/` carries an owner marker bound to
  that directory; tracked state is refused in every mode
  (`refuse_foreign_state`). Never trust state a checkout ships.
- **Security refusals exit 2; "needs your action" exits 1.** Keep the exit-code
  table in `docs/reference.md` in step with `cli.py`.
- **No framework.** Add no plugin system preemptively. Add one focused
  subprocess adapter only when a real language or tool has structured output,
  a tested failure contract, and a repository that needs it. Keep campaign
  state, verification, and review schemas stable; keep tool-specific raw
  output opaque.

## Testing

```bash
npm ci        # pinned Fallow, ast-grep and jscpd for the analyzer tests
npm run check # compiles, then runs every test module
```

One module at a time (`-s tests` puts the shared test helpers on the import
path): `PYTHONPATH=src python3 -m unittest discover -s tests -p test_cli.py`.
The Rust tests skip where cargo, ast-grep or jscpd is missing, and a few process
tests run only on macOS. Running hangover on this checkout prints a Rust
manifest notice for `tests/fixtures/rust/`; that is expected, since the
repository has no root `Cargo.toml`.

A security fix needs a regression test that plants a repository with a
canary outside it and asserts both the exit code and that the canary never
appears in output or stored state. Watch the test fail on the unfixed code
before you trust it.

## Changes

Record user-visible changes in `CHANGELOG.md`, and update the page under
`docs/` (or the README) that describes the behaviour you changed. Report
vulnerabilities privately through GitHub security advisories, not public
issues.
