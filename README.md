# agent-hangover

Clean up a codebase after a long stretch of AI-assisted coding, without changing what it does.

Months of agent edits and deadlines leave dead exports, duplicate helpers, one-caller abstractions and tests that pin implementation details. Ask an agent to "clean this up" and it will happily delete something that mattered or loosen a test until it passes. `hangover` is a command-line harness that makes each cleanup prove itself: the repository's own tests, a pinned static analyzer and a separate reviewer with a fresh context all have to agree before an item closes, and the backlog survives from one session to the next.

It is for developers, and the coding agents working for them, on TypeScript/JavaScript repositories (deepest support) and Rust Cargo workspaces (experimental).

> Are you an AI agent setting this up for someone? Read [docs/agent-setup.md](docs/agent-setup.md).

## Quick start

You need macOS or Linux, Python 3.11+, Node 22+ with npm, and Git. hangover is not on the npm registry; install it from GitHub:

```bash
npm install -g --allow-git=root --allow-scripts=@ast-grep/cli \
  git+https://github.com/treygoff24/agent-hangover.git
hangover doctor
```

The two flags matter on npm 12, which refuses Git installs and blocks dependency install scripts unless told otherwise; older npm accepts them. `hangover doctor` exits 1, naming what is missing, until a reviewer can start: the default is Codex CLI, installed and signed in (see [Choosing a reviewer](#choosing-a-reviewer)).

Then, in a repository whose tests you are willing to run:

```bash
hangover run --no-review     # find the checks, record a baseline, scan, build the backlog
hangover next                # the highest-priority item, with its evidence
```

`hangover run` prints, trimmed:

```text
checks: test (npm run test)
baseline: 20261023T145218Z-scan-4e7034
  test: passed (baseline)
  fallow: completed | mode syntactic | health 85.0 | dead 3 | clones 0
issues: obsolete=0, open=3, stale=0
next: dslp-9a2d94daa6 [P1] Unused export: formatNameLegacy in src/format.js
```

`--no-review` skips the model review; drop it once a reviewer is set up. In a checkout you do not trust, use `hangover run --no-checks --no-review` instead, which runs none of the repository's code (see [Trusted and untrusted checkouts](#trusted-and-untrusted-checkouts)).

## How a campaign works

A *campaign* is one repository's cleanup, kept in a local `.hangover/` directory. Its backlog holds *cards*: findings from the analyzers and from the reviewer, each with an ID, evidence, a priority and the behavior a fix must preserve. A campaign is four commands, repeated:

```bash
hangover run                         # discover the gate, record a baseline, scan, review, build the backlog
hangover next                        # pick the highest-priority card
hangover fix dslp-9a2d94daa6         # lock a batch and print its fix packet; then you (or your agent) edit
hangover verify --issue dslp-9a2d94daa6   # gate + analyzers + a fresh reviewer; closes the batch only if all pass
```

The *gate* is the repository's own checks (tests, types, lint, build), which `hangover init` finds in `package.json` scripts, a Makefile, Cargo or pytest, and writes to `.hangover/config.json` for you to read and edit. `hangover fix` changes no code: it prints a *fix packet*, the evidence plus the invariants the change must keep, for whoever makes the edit. `hangover verify` then runs the cheap checks first (`git diff --check`, the analyzers), the gate once, and a *fresh review*: a separate model run that sees only the diff and the evidence, never the backlog or earlier verdicts, and must agree that no behavior was deleted and no test weakened. A check that already failed at the baseline does not count against you if it still fails the same way; a new failure does.

Work too risky to touch is recorded instead of gamed: `hangover fix <id> --defer "reason"`. A false positive becomes repository policy with `hangover suppress <id> --reason "..."`, which writes the analyzer's own ignore setting where it has one. Analyzer findings are evidence, not proof: in the small repository behind the output above, Fallow also flagged `index.test.js` as an unused file, because `node --test` finds test files by their names, not through imports. Read the card before you delete.

The full loop (releasing part of a batch, retrying a failed review, parallel worktrees, how the gate is staged and reused) is in [docs/workflow.md](docs/workflow.md).

## Is this the right tool?

It fits when:

- the repository is TypeScript/JavaScript, or a Rust Cargo workspace, and has tests you trust as the definition of "still works";
- you want cleanup done in small, verified batches by an agent, with a record of what was fixed, deferred and why;
- you want a second model family to review the first one's work (one flag with a [delegate](https://github.com/treygoff24/delegate-agent) lane).

It does not fit when:

- the repository has no checks at all (tests, types, lint). `verify` then refuses to close anything unless you pass `--model-only`, and a model review alone is weak evidence;
- you want an auto-fixer or a score to push down. hangover never edits product code itself and treats a health score as directional;
- the code is in another language. You get native checks, a backlog and model review, but no dead-code or duplication analyzer;
- the code may not leave your machine. Review sends source to a model provider; use `--no-review`, or `--runner none` and a reviewer you run yourself;
- you are on Windows.

Compared with what you might do instead:

| | Finds candidates | Checks behavior is unchanged | Independent review | Remembers decisions |
|---|---|---|---|---|
| Run Fallow, knip or a linter yourself | yes | no | no | no |
| Ask a coding agent to clean up | sometimes | only if it runs the tests | no (it grades itself) | no |
| hangover | yes (pinned analyzers + review) | your gate, before and after | yes, fresh context | yes, `.hangover/state.json` |

## Trusted and untrusted checkouts

hangover runs as you, with your permissions. It is a quality harness, not a sandbox.

The default, executing mode, runs the repository's checks and, for a Cargo workspace, cargo, whose build scripts and proc macros are the repository's code. Use it only on a checkout you would build and test yourself. `verify` and `audit` always execute.

Static mode (`hangover run --no-checks`, `hangover scan --no-checks`) runs nothing the repository controls. It skips the checks, cargo and Fallow entirely. It accepts only a regular clone, refusing a linked worktree, a submodule, a `.git` that shares objects with another repository, and a git config that uses `include.path` or `includeIf`. It runs git with every repository-configured filter, hook and driver disarmed and a 120-second deadline, which needs git 2.42 or newer. Add `--no-review` to keep the source away from a model too.

In every mode, hangover refuses a file the repository names (a gate script, `package.json`, a Cargo manifest) when its path is absolute, contains `..`, passes through a symlink, is a hard link or resolves outside the repository. A gate of `bash ../shared/gate.sh` is refused even in a repository you trust; move the script inside. It also refuses a `.hangover/` directory the repository tracks, since that state chooses which commands hangover runs.

Every rule and its exact limits are in [docs/trust-model.md](docs/trust-model.md).

## Choosing a reviewer

| Runner | Uses | Setup |
|---|---|---|
| `codex` (default) | [Codex CLI](https://github.com/openai/codex) in its read-only sandbox | install Codex, `codex login` |
| `delegate` | [delegate](https://github.com/treygoff24/delegate-agent), which routes to Codex, Claude Code and other agent CLIs | `pipx install delegate-agent-cli`, authenticate the lane |
| `command` | your own executable | [docs/command-review-runner.md](docs/command-review-runner.md) |
| `none` | nobody: hangover writes the prompt and you run a reviewer, then `hangover review --import` | none |

Pick one per command with `--runner`, or set `review.runner` in `.hangover/config.json`. For a risky fix, review with a different model family from the one that wrote it: `hangover verify --issue <id> --runner delegate --lane claude`. The reviewer contract, configuration and fallbacks are in [docs/review.md](docs/review.md).

## Gating new work

`hangover audit` checks a change against its base and fails only on debt the change introduces, never on debt the repository already had:

```bash
hangover audit --base HEAD            # uncommitted work
hangover audit --base origin/main     # a branch, before merge
```

Audit always executes the checks it selects. No hook or CI file is installed; wire it in yourself once you know its latency and false-positive rate in that repository.

## Using it from a coding agent

hangover ships an agent skill, [`skills/hangover/SKILL.md`](skills/hangover/SKILL.md), that drives one fix batch at a time through the CLI. Link it into your agent's skills directory:

```bash
SKILL="$(npm root -g)/agent-hangover/skills/hangover"
mkdir -p ~/.claude/skills ~/.agents/skills
ln -s "$SKILL" ~/.claude/skills/hangover     # Claude Code
ln -s "$SKILL" ~/.agents/skills/hangover     # Codex, pi, and other agents that read ~/.agents/skills
```

Then ask: `$hangover rehabilitate this repository one safe batch at a time` in Codex, or `/hangover` with the same request in Claude Code. Every command that agents parse takes `--json`; the envelope and exit codes are in [docs/reference.md](docs/reference.md).

## What it will not do

- Edit product code. `fix` prints a packet; you or your agent make the edit.
- Apply analyzer autofixes (`fallow fix` is never run), install hooks, edit CI, or install the target repository's dependencies.
- Optimize line count or treat a score as the goal.
- Commit anything, or touch tracked files except through `suppress`, which edits `.fallowrc.json` or `.hangover-rust.json`.

It writes `.hangover/` and Fallow's `.fallow/` cache, and lists both in the repository's local `.git/info/exclude` rather than its `.gitignore`; for Rust it also builds into a `hangover` directory inside cargo's target directory. `.hangover/` holds logs and patches that can contain whatever your checks print, secrets included. Keep it private and uncommitted.

## Install in detail

Requirements:

- macOS or Linux (hangover relies on POSIX process groups and `flock`);
- Python 3.11+ as the first `python3` on your `PATH`, Node 22+ with npm, and Git (2.42 or newer for `--no-checks`);
- a reviewer, for automated review (see [Choosing a reviewer](#choosing-a-reviewer)); without one, use `--runner none` or `--no-review`;
- for Rust repositories: cargo with clippy, and optionally `cargo install cargo-machete` for unused-dependency findings.

npm installs hangover together with its exact-pinned analyzers, Fallow 3.31.0, ast-grep 0.50.0 and jscpd 5.4.1, in hangover's own `node_modules`; it never uses copies on your `PATH`. Two equivalent commands land in npm's global bin directory (`$(npm prefix -g)/bin`, which must be on your `PATH`): `hangover` and `agent-hangover`. Use `agent-hangover` if another tool owns the shorter name. The unrelated npm registry package called `hangover` is not this tool.

`--allow-scripts=@ast-grep/cli` lets ast-grep's postinstall step copy its native binary into place (no network fetch). When npm 12 blocks that step, ast-grep falls back to a slower path that prints `[warn] postinstall script did not run` on every call. Do not install with `--ignore-scripts`. The launcher, `bin/hangover`, re-runs the first `python3` on your `PATH` in isolated mode (`python3 -I`), so `PYTHONPATH` and a `json.py` in your working directory cannot shadow its imports.

To install a specific checkout or release, pack it and install the tarball:

```bash
npm pack                                   # in a clone; writes agent-hangover-<version>.tgz
npm install -g --allow-scripts=@ast-grep/cli ./agent-hangover-0.1.0.tgz
```

To work on hangover itself, use a clone. `bin/hangover` runs the source in place, so keep the clone where it is. `npm install -g .` is not a substitute: npm links the folder instead of copying it, and the analyzers are missing unless you ran `npm ci` there first.

```bash
git clone https://github.com/treygoff24/agent-hangover.git
cd agent-hangover
npm ci                                     # the pinned analyzers, into the clone's node_modules
mkdir -p ~/.local/bin                      # or any directory on your PATH
ln -s "$PWD/bin/hangover" ~/.local/bin/hangover
```

### Update

```bash
npm install -g --allow-git=root --allow-scripts=@ast-grep/cli \
  git+https://github.com/treygoff24/agent-hangover.git
hangover doctor
```

From a clone: `git pull --ff-only && npm ci`. A new version can change the verifier or an analyzer's version; finish or re-run pending verifications afterwards, and run `hangover scan --rebaseline` when a scan says the baseline is not comparable.

### Uninstall

```bash
npm uninstall -g agent-hangover
rm -f ~/.claude/skills/hangover ~/.agents/skills/hangover    # the skill links, if you made them
```

For a clone, remove the links you made (`~/.local/bin/hangover` and the skill links) and then the clone. A repository's `.hangover/` and `.fallow/` directories stay until you delete them; the state inside is plain JSON.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `npm error code EALLOWGIT` | npm 12 refuses Git installs by default. Add `--allow-git=root`. |
| `[warn] postinstall script did not run` from ast-grep | npm blocked ast-grep's install script. Reinstall with `--allow-scripts=@ast-grep/cli`. |
| `hangover: command not found` | npm's global bin directory is not on `PATH`. Add `$(npm prefix -g)/bin`, or call `agent-hangover`. |
| `hangover: needs Python 3.11 or newer` | Put a newer `python3` first on `PATH`. |
| `Codex is not logged in, so the default reviewer cannot run and nothing has run yet` (exit 2) | Run `codex login`, choose another runner, or pass `--runner none` or `--no-review`. |
| `refusing symlinked or external gate script '../shared/gate.sh'` (exit 2) | A file the repository names lives outside it. Move it into the repository as a regular file. |
| `refusing ... under --no-checks: ... is a gitfile` (exit 2) | Static mode reads only a regular clone. `git clone` the checkout and scan the clone. |
| `refusing ... under --no-checks: .git/config includes another file` (exit 2) | Static mode will not follow git config includes. Remove the include, or use executing mode once you trust the checkout. |
| `--no-checks needs git 2.42 or newer` | Upgrade git. |

## Limitations

- Deterministic analysis is deepest for TypeScript/JavaScript (Fallow). Rust support is experimental: its categories and thresholds may change. Other languages get no dead-code or duplication analyzer; `scan`, `run`, `status`, `next` and `audit` say which files no analyzer covered.
- Static mode runs no Fallow, so it gives TypeScript/JavaScript no deterministic analysis, and Rust only the source-level part.
- Check discovery reads the repository root only. Configure monorepo package checks by hand in `.hangover/config.json`.
- Baseline comparison classifies failures by command outcome, not by the meaning of each diagnostic line.
- A fresh context decorrelates the reviewer's reasoning, not its model family's blind spots; choose a different family for risky fixes.
- `audit` requires Git. No security scanner is invented; the repository's own security commands are reused.
- Captured command output is not redacted.

## Documentation

- [docs/agent-setup.md](docs/agent-setup.md): install and first run, written for an AI agent doing it for someone
- [docs/workflow.md](docs/workflow.md): the fix loop, `audit`, gate staging and reuse, parallel worktrees, check discovery
- [docs/trust-model.md](docs/trust-model.md): executing and static mode, file containment, shipped state, safety rules
- [docs/review.md](docs/review.md): the reviewer contract, runners, configuration and fallbacks
- [docs/command-review-runner.md](docs/command-review-runner.md): plugging in your own reviewer
- [docs/analyzers.md](docs/analyzers.md): Fallow and Rust findings, card identity, analyzer upgrades
- [docs/reference.md](docs/reference.md): every command, exit codes, JSON output, `.hangover/` layout
- [CHANGELOG.md](CHANGELOG.md)

## Security

A way for a repository to make hangover read outside itself, run its code in static mode, or choose hangover's checks or reviewer is a security bug. Report it privately through this repository's GitHub security advisories ("Report a vulnerability" under the Security tab), not in a public issue. See [docs/trust-model.md](docs/trust-model.md#reporting-a-vulnerability).

## Development

```bash
npm ci
npm run check      # compiles, then runs every test module
```

The tests use only Python's standard library and throwaway Git repositories. [AGENTS.md](AGENTS.md) has the rules every change must keep.

## License

MIT. See [LICENSE](LICENSE).
