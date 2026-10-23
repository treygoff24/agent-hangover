# agent-hangover

`hangover` is a small, agent-first codebase rehabilitation harness. It preserves externally observable behavior while reducing conceptual surface area: dead machinery, duplicated concepts, unearned abstractions, speculative compatibility, needless indirection, and tests that protect implementation trivia.

It combines four things that should not evaluate themselves:

1. repository-native tests, types, lint, build, and security commands;
2. pinned deterministic analysis: Fallow for TypeScript/JavaScript, and (experimental) clippy, ast-grep, jscpd and cargo-machete for Rust Cargo workspaces;
3. a fresh-context LLM simplification review;
4. persistent local campaign state across incremental fixes.

It does not optimize line count, auto-apply analyzer fixes, install hooks, edit CI, or make a score the source of truth.

## The idea

Repeated agent edits and deadlines can leave dead exports, duplicate helpers, one-caller abstractions, and tests tied to implementation trivia. `hangover` exists to remove that machinery without changing what the code does. The repository's own gates, a pinned deterministic analyzer, a fresh-context reviewer, and a persistent backlog check each other. The reviewer receives declared changes as claims to verify, not authority to relax the contract; prior verdicts are not review inputs.

A campaign is four commands:

```bash
hangover run        # discover gates, baseline, scan, review, build the backlog
hangover next       # highest-priority item with evidence and invariants
hangover fix <id> [<id> ...]   # lock one coherent batch and emit its fix packet — then you edit
hangover verify --issue <id>   # deterministic gate + fresh adversarial diff review
```

`hangover fix` deliberately changes no product code. It gives a person or agent a packet of evidence and behavioral invariants, and the item closes only when the native gate passes *and* an independent reviewer, seeing only the diff and the evidence, agrees no behavior was deleted and no tests were weakened. Work too risky to touch is recorded honestly with `hangover fix --defer "reason"` instead of gaming the backlog.

For new work, `hangover audit --base <ref>` gates only the debt a change introduces, never the debt the repository already had. And because the reviewer is pluggable, having a different model family review a fix than the one that wrote it is a one-flag choice.

## Architecture

```text
hangover CLI (stable interface)
├── repo discovery + native checks
├── Fallow 3.31.0 subprocess (opaque advisory JSON)
├── Rust analysis: cargo metadata + clippy, ast-grep 0.50.0, jscpd 5.4.1, cargo-machete (optional)
├── ephemeral pluggable reviewer (schema-constrained JSON)
└── .hangover/ state + immutable run artifacts

Codex / Claude skill ── drives one fix batch at a time through the CLI
```

The MIT-licensed implementation is a dependency-free Python CLI. Fallow, ast-grep and jscpd are exact-pinned npm dependencies of hangover itself, installed in hangover's own `node_modules` and never looked up on `PATH`; Rust analysis uses the cargo and clippy on your `PATH`. Target repositories receive no dependencies or configuration changes.

## Install

Requirements:

- macOS or Linux (hangover relies on POSIX process groups and `flock`);
- Python 3.11+, Node 22+ with npm, and Git (2.42 or newer for `--no-checks`);
- for automated fresh review, one runner: Codex CLI (the default), a `delegate` CLI, or your own command (see "Fresh-context review"). Without one, use `--no-review` or `--runner none` and review the prepared packet yourself;
- for Rust repositories: cargo with clippy, and optionally `cargo install cargo-machete` for unused-dependency findings.

hangover installs with npm, which also installs its pinned analyzers (Fallow, ast-grep, jscpd) beside it, where hangover looks for them. It is not published to the npm registry, so install it from the Git repository:

```bash
npm install -g git+https://github.com/treygoff24/agent-hangover.git
hangover doctor
```

The npm package is named `agent-hangover`. npm puts two equivalent commands, `hangover` and `agent-hangover`, in its global bin directory (`$(npm prefix -g)/bin`), which must be on your PATH. This README uses `hangover`; use `agent-hangover` if another tool already owns the shorter command. The unrelated npm package named `hangover` is not this tool. The package's analyzers are exact-pinned dependencies (`fallow` 3.31.0, `@ast-grep/cli` 0.50.0, `jscpd` 5.4.1) and its `files` list ships only the launcher, the Python source, schemas, prompts, the skill and the review-runner recipe. `@ast-grep/cli` runs a postinstall script that copies its binary out of the platform package npm already installed (no network fetch), so do not install with `--ignore-scripts`.

The launcher, `bin/hangover`, runs the first `python3` on your PATH, which must be 3.11 or newer, and immediately re-runs it in isolated mode (`python3 -I`): `PYTHONPATH` and the other `PYTHON*` variables, the user site directory, and the current directory do not reach hangover's imports, so a `json.py` in the directory you run from cannot shadow the standard library. It then puts its own `src/` first on the import path.

To install a specific checkout or release instead, pack it and install the tarball:

```bash
npm pack                                       # in a clone; writes agent-hangover-<version>.tgz
npm install -g ./agent-hangover-0.1.0.tgz
```

`npm install -g .` from a clone does not do the same thing: npm links the folder rather than copying it, and does not install the analyzers into it unless you ran `npm ci` there first. For working on hangover itself, use a clone:

```bash
git clone https://github.com/treygoff24/agent-hangover.git
cd agent-hangover
npm ci                                         # the pinned analyzers, into the clone's node_modules

mkdir -p ~/.local/bin                          # or any directory on your PATH
ln -s "$PWD/bin/hangover" ~/.local/bin/hangover
```

`bin/hangover` runs the Python source in place, so keep that clone where it is.

`hangover doctor` reports the Python, Node, Fallow and (in a Cargo repository) Rust tool versions, checks that the configured reviewer can start, and exits 1 naming anything missing. `hangover doctor --json` prints the same report as one JSON object.

The agent skill lives in `skills/hangover/SKILL.md`, which the npm install includes. To use it from an agent, link that directory into the agent's skills directory, for example for Claude Code:

```bash
mkdir -p ~/.claude/skills
ln -s "$(npm root -g)/agent-hangover/skills/hangover" ~/.claude/skills/hangover   # from a clone: "$PWD/skills/hangover"
```

Other agents that read `SKILL.md` skill folders take the same directory in their own skills location.

The Python module is `hangover`: from a clone, `PYTHONPATH=src python3 -m hangover --version`
runs the same CLI. Prefer the launcher for normal use because it isolates imports.
For an existing development install or campaign, see the breaking rename and
manual migration steps in [CHANGELOG.md](CHANGELOG.md) before initializing state.

## First run

In a repository you trust:

```bash
hangover run
```

That one command initializes local state, discovers the repository gate, runs it to record a baseline, runs Fallow and (for a Cargo workspace) the Rust analysis, invokes a fresh subjective review, persists the backlog, and prints the next remediation. `hangover run --runner none` prepares the review packet instead of invoking a reviewer; `--no-review` skips the review.

In a checkout you do not trust yet, start with static mode:

```bash
hangover run --no-checks --no-review
cat .hangover/config.json
```

Static mode runs no check, executes no repository code and does not run Fallow (see "Trust model" for exactly what that covers), and `--no-review` keeps the source away from a model provider. It works only on a regular clone: run it on a fresh `git clone`, not on a linked worktree or from inside a submodule. Inspect the discovered checks before you run anything that executes them. Once the checkout is trusted, `hangover scan --rebaseline --checks` records a full baseline, Fallow and the native checks included.

### Invoke the installed skill

```text
$hangover rehabilitate this repository one safe batch at a time
```

From Claude Code, invoke `/hangover` with the same request.

## Trust model

hangover is a quality harness, not a sandbox. It runs as you, with your permissions, files and credentials.

**Executing mode** is `run` and `scan` without `--no-checks`, every `verify` and `audit`, `suppress` (its rebaseline scan), and any command that invokes a `command` reviewer. These can run repository-controlled code:

- the configured native checks (`run`, `scan --checks`, `verify`, `audit`), with your normal environment;
- for a Cargo workspace, `cargo metadata`, `cargo clippy` and `cargo machete` (every analyzer scan outside static mode, plain `scan` without `--checks` included). Clippy compiles the workspace, so the repository's build scripts and proc macros run, and rustup obeys its `rust-toolchain.toml`. `audit` builds the base commit too;
- a `command` review runner from `.hangover/config.json`, which is an unsandboxed subprocess.

Use executing mode only on a checkout you would be willing to build and test yourself.

**Static mode** (`run --no-checks`, `scan --no-checks`) is for reading a checkout you do not trust. It guarantees, as far as the code below goes:

- no configured check runs, and cargo, rustup, clippy and cargo-machete are never started. Rust analysis reads the `Cargo.toml` files as data and the sources with the bundled ast-grep and jscpd; clippy and cargo-machete sections are `skipped`, so the Rust result is `partial`;
- Fallow does not run. Its section is `skipped`, which is not a failure (`scan` and `run` still exit 0): Fallow follows `tsconfig` `extends` chains, `node_modules` manifests and plugin files, which a checkout can point outside itself, and no precheck can bound that. TypeScript and JavaScript sources therefore get no deterministic analysis in static mode, and existing Fallow cards are left as they were;
- only a regular clone is read. The directory holding `.git` must have a real `.git` directory with no `commondir` file, no `objects/info/alternates` and no symlink inside it (its `hooks/` directory aside). A gitfile (a linked worktree, a submodule's own directory, or any other pointer to a git directory elsewhere) is refused, and so is a config whose `core.worktree` moves the work tree. Scan a fresh `git clone` of the checkout instead. git is told never to discover a bare repository (`safe.bareRepository=explicit`), so a directory that is itself a bare repository is read as a plain tree, not through git;
- before any git runs in the checkout, hangover reads `.git/config` (and `.git/config.worktree`) itself, with includes off, and refuses a config that uses `include.path` or `includeIf.*.path`: git would read the included file, wherever it is, for every command;
- every git command run in static mode reads no system or global git config, takes attributes from the empty tree (so `.gitattributes` selects no filter or diff driver), turns `core.fsmonitor`, `core.hooksPath`, the pager, editor, ssh, askpass and credential helper off, and overrides with an empty value every command-valued key the repository's config defines (filter, textconv, diff and merge drivers, pagers, gpg programs, remote commands, config-defined hooks). No transport is allowed, whatever `protocol.*.allow` the repository sets, and no missing object is fetched from a promisor remote (an `ext::` remote URL is a command). The exclude, attributes, diff order and mailmap files a config could name are all `/dev/null`, so git opens no file outside the checkout because the config says to. `git status` does not descend into submodules. This needs git 2.42 or newer; on older git, static mode refuses to start;
- every git command has a deadline of 120 seconds (`STATIC_GIT_TIMEOUT_SECONDS` in `src/hangover/repository.py`). A FIFO or device where git expects a file would otherwise stall it; past the deadline the run is refused;
- ast-grep and jscpd get hangover's own configuration, so the repository's `sgconfig.yml`, `.jscpd.json` or `jscpd` key in `package.json` is never read;
- a file the checkout holds as a hard link (more than one name for one file, which a git checkout never makes) is left out of the file list, with a note;
- an existing `.hangover/` is used only if hangover's owner marker binds it to this directory (see "State the checkout ships" below).

The rule for files the repository names (below) holds in static mode as in every other.

What static mode does not do:

- it is not a sandbox. git and the bundled analyzers are third-party binaries reading untrusted input, with your permissions;
- a review, unless you pass `--no-review`, sends the source to the configured model provider, and a `command` runner executes;
- a static scan cannot become a rebaselined baseline: `scan --rebaseline --no-checks` is blocked (exit 2) whenever it skipped Fallow or ran the Rust analysis without cargo. The very first scan of a campaign is recorded as its baseline whatever the mode; after a static first scan, run `hangover scan --rebaseline` once the checkout is trusted, which records Fallow and the full Rust analysis.

**Files the repository names (every mode).** hangover reads some files because the repository points at them or by convention: `package.json` and workspace manifests, the gate script a `package.json` script runs, the `Makefile`, the Cargo manifests (root, ancestors and members), Rust sources, `.hangover-rust.json`, the analyzed root's `clippy.toml`, `.fallowrc.json` (for `suppress`), lockfiles and other verification inputs, the files a finding cites, and untracked files shown in review patches. In every mode, such a path is refused if it is absolute, has a `..` component, has a symlink in any component (the file itself included), is a hard link, or resolves outside the repository. A refused file is never opened, hashed or printed, and the command exits 2. The file list git reports gets the same rule: an entry that is absolute, has an empty, `.`, `..` or `.git` component, leads through a symlinked directory or resolves outside the repository refuses the whole scan (only a hand-built index can hold one). A tracked symlink itself is skipped, not refused: hangover reads no symlink. Lookups that only ask whether a file exists (`tsconfig.json`, the lockfile that picks the package manager, `node_modules`) treat a symlink as absent.

This applies to repositories you trust, too, and that is deliberate: no mode reads, stores or prints a file outside the checkout because the checkout pointed at it. A gate such as `"verify": "bash ../shared/gate.sh"`, or a `package.json` that is a symlink into a shared directory, is refused: `init` (and so `run` on a new campaign) and `doctor` exit 2 on such a gate, and every scan exits 2 on such a `package.json`. Move the script into the repository as a regular file. The environments hangover gives git and its analyzers also drop relative `PATH` entries, so the checkout cannot supply the `node` or `git` they run (native checks keep your normal environment).

A refused scan merges nothing and is never saved as the baseline or the latest run; `status` exits 2 and names the refusal until a scan completes.

**State the checkout ships.** Everything hangover reads from `.hangover/` (the checks and review command in `config.json`, `state.json`, run snapshots, gate proofs) is trusted as its own, so two rules keep a checkout from supplying it:

- in every mode, a `.hangover/` path the repository tracks (in any letter case) is refused by every command except `hangover fallow`. hangover never commits `.hangover/`, so tracked state came with the checkout. Remove it from the index (`git rm -r --cached .hangover`) and delete the directory if you did not create it;
- in static mode, an existing `.hangover/` must carry hangover's owner marker (`.hangover/owner`), which records the repository path and the device and inode of `.hangover/` itself, so an archive cannot forge it. `hangover init` writes the marker when it creates the directory and adopts an existing one when you run it. A campaign made by an older hangover, or moved or copied to a new path, needs `hangover init` once before `--no-checks` will use it.

Executing commands still accept an unmarked, untracked `.hangover/` (a campaign from an older hangover), so if the checkout came with one, read `.hangover/config.json` or delete the directory before running anything beyond static mode.

The `codex` and `delegate` review runners ask those tools for their read-only modes; that guarantee belongs to the invoked tool (see "Reviewer contract").

## Rehabilitation workflow

```bash
hangover run
hangover status
hangover next
hangover fix dslp-0123456789 [dslp-9876543210 ...]

# The invoking agent reads the fix packet, establishes Chesterton's Fence,
# edits one coherent batch, and runs narrow checks while working.

hangover verify --issue dslp-0123456789
hangover next
```

`hangover fix` deliberately does not mutate product code. It locks one coherent batch, captures the pre-edit patch, and emits the evidence/invariants packet used by the invoking Codex or Claude agent. `hangover verify` runs the deterministic evidence (cheap first, see "Gate cost") and a separate adversarial reviewer once; it resolves every item in the batch only when both pass.

Select only the issues you intend to fix. If a batch is too broad, release named
members without deferring the rest:

```bash
hangover fix --release dslp-9876543210
hangover verify  # uses the surviving primary, including after primary release
```

Unfinished released members return to open. Already settled members keep their
disposition. Survivor evidence and the original fix base remain intact. Scans
detach stale or otherwise settled members left in older batch state; an ordinary
active finding disappearing still requires verification and fresh review.
`verify --accept` waivers apply to the whole active batch, not future remediations.

If only the reviewer failed, reuse the unchanged deterministic proof explicitly:

```bash
hangover verify --retry-review --runner delegate --lane claude --json
```

Retry hashes the recorded inputs and artifacts again, then runs only a new review.
It keeps the original proof/run and refuses code, policy, tool, note, waiver, or
membership drift. Do not combine it with notes, acceptance waivers, or
`--no-review`; those need ordinary verification. Recovery actions retain the
selected reviewer rather than quietly falling back to another route. A known
engine, model, or effort contradiction between Delegate preflight and its reported
execution is a tool error, never approval. Missing reported metadata stays unknown.

Fix packets use format version 2: `issue` identifies the primary and fix directory,
`issues` contains the full member contracts, and `remediation` carries shared facts
once. The full starting context remains in `fix-context.json`. Resume projects
current facts without rewriting the original packet or evidence. Review packets
likewise avoid repeated shared fields and prior verdicts; their full audit-only
context is retained and hashed, but is not sent as fresh-review input.
A run-local `review-schema.json` is named in the packet and prompt, so manual
reviewers can stay within the supplied artifact boundary. It is covered by the
same prepared-artifact hashes.

For a bounded initial review:

```bash
hangover review --scope src/domain --scope src/api --json
```

Scope accepts repository-relative files or directories, not globs. It cannot
narrow post-fix or prevention review. Initial review imports use the selection
requested on the import command; only the reviewer's reported files get coverage
credit. A wider selection leaves additional files explicitly unreviewed. Legacy
stored verdicts without `reviewed_files` get no coverage credit; new imports must include it. Current
schema-producing runners include the field. Counts and a coverage-artifact path
are returned in JSON; the full manifest is retained separately. Coverage is
self-reported and never an exhaustive or clean-codebase claim.

For a custom Claude command runner and its live evidence, see the
[command review recipe](docs/command-review-runner.md). Leave risky work explicit
with a recorded reason, rather than treating it as completed.

```bash
hangover fix dslp-0123456789 --defer "Dynamic plugin registration has no safe local parity test"
```

## Prevention / changed-code audit

For uncommitted work:

```bash
hangover audit --base HEAD
```

Before merge:

```bash
git fetch origin main
hangover audit --base origin/main
```

Audit mode runs `git diff --check` (including untracked text files), Fallow's changed-code `audit`, and discovered lint/type/security commands; when none of those exist (for example, only a combined `verify` gate was discovered), it runs every configured check and says so. Fallow labels introduced versus inherited findings and gates only introduced debt. For a Cargo workspace it also runs the Rust analysis on this tree and on the base commit and fails on any Rust card the base does not have (see "Rust integration"). Add `--full` to run every configured native check.

Audit has no static mode: it runs the selected checks and, for Rust, cargo on both trees. Audit only a checkout you trust to execute. An audit whose analyzer did not complete (Fallow failed, or the Rust analysis is `failed` or `partial`) is a `tool_error` and exits 2, never a pass.

Require a fresh review of the entire exact proposed change when that policy is
appropriate:

```bash
hangover audit --base HEAD --full --require-review --json
hangover audit --base HEAD --full --require-review --prepare --json
```

The second form seals the gate, patch, and review inputs without invoking a
reviewer. Give the returned `review_prompt` to a fresh read-only reviewer, then
follow the exact `next_action` after its verdict is written. That import reuses
the original gate and resolved base, checks the token and all input/artifact
hashes, and consumes approval once. A remediation receipt cannot stand in for
this whole-change review. The default audit remains detector/native-gate-only;
it is not an architectural approval.

Reviewed audit accepts the same runner/lane/model/effort options as verification.
Those options, `--prepare`, and `--import` require `--require-review`. A new
reviewed audit supersedes the old pending proof before running gates, even if
the new gate fails. Do not start another while its reviewer is working. Failed
transports retain their output and offer a separate manual-verdict path; they
do not turn an incomplete runner into a pass. Ignored dependencies, external
services, arbitrary command environments, and transitive tool installs are not
frozen by these local receipts.

No hook or CI file is installed automatically. If you choose to add one, use the
default audit command below. First establish acceptable latency and false-positive
behavior in that repository.

```bash
hangover audit --base HEAD
```

## Commands

| Command | Purpose |
|---|---|
| `hangover init [--force] [--stages-from-gate] [--ignore-legacy]` | Discover checks and create `.hangover/` state. `--stages-from-gate` adopts the commands of a gate shell script as explicit ordered checks (see "Gate cost"). `--ignore-legacy` explicitly starts fresh instead of migrating an old campaign. |
| `hangover scan [--checks \| --no-checks] [--rebaseline]` | Capture analyzer evidence (Fallow, and Rust for a Cargo workspace) and compare it with the original baseline. Analyzers only by default (for Rust that still runs cargo, so build scripts run); `--checks` also runs the configured checks; `--no-checks` is static mode (no checks, no Fallow, Rust without cargo; regular clones only; see "Trust model"). `scan --rebaseline --checks` records which stages are red; `scan --rebaseline --no-checks` is blocked. |
| `hangover status [--json] [--stale]` | Show campaign runs, issue counts, and the next item; `--stale` lists both stale and obsolete terminal issues. |
| `hangover next [--json]` | Resume active work or select the highest-priority open remediation. |
| `hangover list [--json] [--source SOURCE] [--category CATEGORY] [--status STATUS] [--file PATH] [--group-by dir\|file\|category] [--sort lines] [--exclude-tests]` | Filter concise issue records; each filter is repeatable. `--group-by` summarizes findings (dir adds source-line counts), `--sort lines` orders by duplicated-line weight, `--exclude-tests` drops tests/spikes/docs/fixtures by path convention. A finding touching several directories or files counts its full weight in each group, so group totals are not additive; directory source-line counts include test files even with `--exclude-tests`. `status` also prints a recorded baseline-to-latest delta line. |
| `hangover preview [ISSUE ...] [--limit N] [--json]` | Inspect candidate members, shared files, overlap, and outliers without activating work. |
| `hangover review [--runner {codex,delegate,command,none}] [--lane LANE] [--model MODEL] [--reasoning-effort EFFORT]` | Run a fresh initial subjective review with the configured or selected runner. |
| `hangover review --prepare` | Write a packet without invoking a runner. |
| `hangover review --import FILE` | Import schema-conforming review JSON. |
| `hangover dedupe [--apply] [--json]` | Report duplicate candidates; `--apply` merges only same-remediation matches and leaves overlap-only suggestions open. |
| `hangover fix [ISSUE ...] [--json]` | Start one coherent remediation batch or resume an open batch's primary without resetting evidence. `--branch NAME` records the batch against a branch and lets it be open beside another batch; `fix PRIMARY ID... --add` adds cards to an open batch under the same membership rules. See "Campaigns with parallel worktrees". |
| `hangover packet ISSUE... [--out FILE [--force]] [--json]` | Write a fix packet for a set of cards without activating anything; stdout by default. `--out` refuses anything inside a `.hangover` or git directory (symlinks followed) and an existing file unless `--force`. |
| `hangover fallow -- ARGS` | Run the pinned Fallow in this checkout (`--root` set, same environment as hangover's scans), so a worktree lane sees exact clone spans and the like. Read-only: analysis and inspection commands only; `fix`, `init`, `migrate`, `hooks`, `watch` and the like, write flags (`--yes`, `--save-*`, `-o/--output-file`, `--sarif-file`) and `--root` overrides are refused. |
| `hangover verify --issue ISSUE [--runner {codex,delegate,command,none}] [--lane LANE] [--model MODEL] [--reasoning-effort EFFORT] [--accept FINDING_ID --accept-reason REASON] [--merged \| --all] [--model-only]` | Re-run the analyzers and the gate, adversarially review, and resolve on success; `--accept` waives an introduced finding already tracked as its own issue. `--affected` runs the analyzers plus only the checks marked narrow and records a partial proof that resolves nothing. `--fresh-gate` ignores a reusable gate proof. `--merged` verifies every open batch whose branch is merged into HEAD, `--all` every open batch, with one cheap phase and one gate run. See "Gate cost". With no configured checks, verify refuses to resolve anything unless you pass `--model-only`: the analyzers and the model review alone then decide, and the proof is labelled model-only wherever it is shown. `--model-only` is refused when checks are configured. |
| `hangover suppress ISSUE --reason REASON [--no-rebaseline]` | Apply the finding's Fallow config remedy (e.g. `ignoreDependencies`) to the target repo's `.fallowrc.json` (a Rust finding: its key to `ignore` in `.hangover-rust.json`) and mark the issue suppressed. |
| `hangover run [--no-checks] [--no-review] [--runner {codex,delegate,command,none}]` | Initialize, scan, review, and select the next item. `--no-checks` is static mode (no checks, no Fallow, Rust without cargo; regular clones only; see "Trust model"); `--runner` picks the reviewer for this run (`none` prepares the packet without invoking one). |
| `hangover audit --base REF [--full] [--json]` | Gate changed-code regressions without legacy-debt failure. |
| `hangover doctor [--json]` | Report the Python, Node, Fallow and Rust tool versions and Codex/delegate presence; test Codex's read-only sandbox without a model, or dry-run the configured delegate route. The delegate Codex lane also probes a local Codex binary when available. A configured `command` reviewer is reported as a resolved path and never executed. Rust tool versions are probed outside the checkout, so its `rust-toolchain.toml` is not consulted. Exits 1 when something required is missing; `--json` prints the report as one object (`tools`, `missing`, reviewer readiness). |

Use `hangover --repo /absolute/path <command>` to target a repository other than the current directory.

### Exit codes

| Exit | Meaning |
|---|---|
| `0` | The operation completed. Its JSON `state` is one of `ready`, `in_progress`, `review_pending`, `resolved`, `passed` or `no_open_work`; `0` alone does not mean an item resolved. `scan` and `run` exit 0 once they have recorded a scan, so read their printed status for an analyzer that failed (a static scan's `skipped` Fallow is not a failure). |
| `1` | A verdict blocked it (`state: blocked`): a new or changed gate failure in `verify`, an introduced finding, a failed check or `git diff --check` in `audit`, or a post-fix review whose verdict is `fail` or `partial` (from `verify`, or from `review --issue ... --import`). Also: initialization requires an explicit legacy-state migration decision (or `hangover init --ignore-legacy` for a fresh campaign), `doctor` found something required missing, `init --stages-from-gate` adopted nothing, or `suppress` could not verify its rebaseline. |
| `2` | Evidence or execution failed (`state: tool_error`): an analyzer that did not complete in `audit`, a reviewer that failed or returned invalid output, a filesystem error, invalid arguments, or a `scan --rebaseline` whose reset was blocked. Also every security refusal, from whichever command meets it (`init`, `scan`, `run`, `verify`, `audit`, `doctor`, `suppress` and the rest): a file the repository names that breaks the containment rule, a refused git file list, a tracked or (in static mode) unowned `.hangover/`, and in static mode a git location that is not a regular clone, a git config with includes, or a git command past its deadline. A refused scan is never saved as the baseline or latest run, and `status` exits 2 while the last scan stands refused. |

Historical baseline failures do not become regressions merely because they remain red.

### Driving the tool with JSON

`next`, `list`, `preview`, `fix`, `packet`, `verify`, `review`, and `audit` accept `--json`. (`status --json`, `doctor --json` and `dedupe --json` print their own report shapes, not the envelope below.) Normal outcomes and handled errors emit one JSON object on stdout; progress and setup prose go to stderr. The versioned envelope names the command's own run, proof, review run, batch, blockers, artifact paths, and repository-qualified `next_action`. An interleaved scan does not replace those originating IDs. `status --json` remains the separate campaign-state view.

Read `state`, not just the exit code. `review_pending` means approval is still owed, including after `verify --no-review`; `resolved` means the remediation closed. `passed` is an operation result, not a claim that the whole repository is clean. `tool_error` means evidence or execution failed, not a quality verdict. Read-only results report `proof_freshness: not_checked`; a recorded proof ID alone does not promise unchanged inputs. Prepared results name the expected verdict path and the fresh-review prerequisite before their import action can run.

`review-run.json` describes transport/protocol completion, not final approval.
Raw `review.json` is retained even when its route or token is refused. Only the
validated command outcome and consumed proof establish acceptance; do not treat
a passing word in a retained file as a receipt.

```bash
hangover --repo /path/to/repo list --category complexity --file src --json
hangover --repo /path/to/repo preview --limit 3 --json
hangover --repo /path/to/repo next --json
```

Listing, preview, next, and status do not initialize a campaign. A preview describes structural overlap, not proof that the issues share one coherent change. Select only the members you actually intend to fix.


## Gate cost

The configured gate can take many minutes, so verify spends it last and at most once per tree.

- **Cheap evidence first.** `verify` runs `git diff --check`, the Fallow scan and the introduced-findings check (with `--accept`) before any native check. If one of them blocks, the gate does not run and the snapshot records `gate: not_run`.
- Verify queries absent dead-code batch members after other cheap evidence passes. Member-specific unknowns block; repo-wide limits are `not_applicable`. Fingerprints are audit data. Queries mirror scan mode and retry syntactically after type-aware failure. Gate and review remain required.
- **Stages.** `hangover init` splits a combined gate into ordered stages only in one case: a package.json script that is a pure `&&` chain where every element is a package-script invocation through the package manager (`npm run x`, `npm test`, `pnpm x`, `pnpm run x`, `yarn x`, `yarn run x`, `bun run x`) naming a script that exists, with no `pre`/`post` npm hooks on the combined script. Tokens are kept exactly (`npm test` stays `npm test`) and the declared order is kept. Anything else (a direct command such as `node check.js` or `tsc`, an env prefix, shell syntax, a gate shell script) stays one check (`verify`). Auto-split stages carry the script they came from and a hash of its definition; `verify` re-reads the gate first, and if it changed since init it re-discovers the stages, updates `.hangover/config.json`, says so, and records it in the snapshot. Run `hangover scan --rebaseline --checks` afterwards. Checks without `stage_of`/`adopted_from` are explicit configuration the operator owns; hangover never rewrites them, and earlier hangover versions never split gates, so an existing config is left alone.
- **Gate shell scripts are proposed, not guessed.** When the gate is a shell script whose lines read as separate commands, `hangover init` and `hangover doctor` print the proposed stage list and the command to adopt it: `hangover init --stages-from-gate`. That writes the stages to `.hangover/config.json` as explicit checks marked `adopted_from` with the script's hash (the previous config is saved beside it). Adoption is your assertion that this is the gate's order. If the script later changes, `verify` refuses to run and tells you to re-adopt or edit the config; it never runs a stale adopted list as the full gate. A script that is not a plain command list (a wrapper function, version pins, prerequisite checks, as in `run_stage lint npm run lint`) gets a weaker proposal: its unconditional package-script calls in order, including workspace calls such as `npm run build --workspace apps/web`, plus every line those stages do not cover, printed first for uncovered package calls. Conditional calls (`if ...; then npm run x; fi`, `a && npm run x`) are never proposed.
- **Stop at the first blocking stage.** For an auto-split chain or adopted stages (a declared order), verify stops at the first stage whose failure is new (a regression, an unbaselined failure, or a failure that differs from the baseline). Separately discovered scripts (`test`, `lint`, ... with no combined gate) are independent checks and all run. A stage that is red in the baseline is let through only when its failure output is identical to the baseline's and non-trivial (at least 40 bytes after trimming); silent or near-silent identical failures block as unproven. When a stage is let through, the snapshot, the proof record and the output say "passed with pre-existing failure in <stage>". Skipped stages are `not_run`, which blocks.
- **Baseline red stages.** `hangover status` lists the stages that were red in the baseline and the latest gate mode (ran, reused, partial, not run).
- **Reuse.** A gate where every check passed is recorded in `.hangover/gate-proofs.json`. The reuse key is a hash of: the configured check list; the content of tracked and non-ignored untracked files (plus modes and symlink targets); HEAD; the staged index entries; the content of lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb`) and of package-manager install markers (`node_modules/.package-lock.json`, `.pnpm/lock.yaml`, `.modules.yaml`, `.yarn-state.yml`, `.yarn-integrity`); and the path, mode and content hash of ignored files outside dependency and cache directories (`node_modules`, `.cache`, `.venv`, `target`, `coverage`, `.next` and similar). More than 20,000 ignored files or 256 MB of them, any ignored symlink to a directory, or any symlink pointing outside the repository disables reuse for that run, and the output says why. A proof is recorded only when the complete key before the gate equals the complete key after it. So a gate that changes its own inputs (a build that writes different ignored output each run) never records; a deterministic build that rewrites identical content records on its second run and is reusable from the third. A fresh run (including `--fresh-gate`) first discards the entry for the current state, so a failed rerun leaves no older pass reusable. A reused gate is marked `gate: reused ... of run <id>` in the output, the snapshot and the proof record. The environment and the contents of dependency directories are not hashed; `verify --fresh-gate` always reruns.
- **`verify --affected` (opt-in).** Runs Fallow and only the checks whose config entry has `"narrow": true` (discovery marks format, lint and typecheck stages), and records a partial proof. A partial proof is never accepted by review import or resolution and is never reused as a gate proof; only a later full `verify` resolves the batch. Use it for quick feedback between edits, then run the full gate once.
- **Output.** Every check prints what it runs and where its log is; a failing check prints its name, exit status, log path and last output lines, and the JSON result lists `failed_checks`.

## Campaigns with parallel worktrees

State (`.hangover/`) lives in the main checkout only. A coordinator hands each lane a packet and merges the lanes' branches one by one:

```sh
hangover packet ID1 ID2 --out lane-a.json         # hand to a worker; activates nothing
hangover fix ID1 ID2 --branch lane-a              # register the batch (the coordinator, in the main checkout)
hangover fix ID3 --branch lane-b                  # a second batch, open at the same time
# ... workers edit in their own worktrees and commit; the coordinator merges lane-a and lane-b ...
hangover verify --merged                          # prove every open batch whose branch is now in HEAD
```

- A second batch can be open only when it names its branch; a card is in at most one open batch. `hangover status` lists every open batch. `fix <primary>` on a parked batch makes it the one that `verify`, `review` and `release` act on; an old state with one active batch is simply one open batch.
- `verify --merged` (or `--all`) runs `git diff --check`, Fallow and the introduced-findings check once, then the gate once (or reuses the exact-tree proof), and writes a separate proof and fresh review per batch. An introduced finding counts against the batches whose branch changed its files, and against every batch when no branch touched them or a branch's changes cannot be listed. A failing gate or Fallow blocks all of them. A batch with no branch, or whose branch is missing or not merged, is skipped by `--merged` and reported; it stays open. Each batch's review sees the tree diff since its base commit, which can include other merged batches.
- Workers run only read-only commands. If the main checkout of a worktree cannot be determined (bare or removed), every write is refused and reads need `--state-from`. From a linked worktree, `list`, `next`, `status`, `preview` and `packet` read the main checkout's state (found automatically, or `--state-from PATH`); `fix`, `verify`, `scan` and the rest refuse there. `audit` is the exception: it records only to the worktree's own state. `hangover fallow -- <args>` works anywhere.

## Native check discovery

For a root `package.json`, `hangover init` prefers one existing `verify`, `gate`, or `check` script. Otherwise it discovers test, typecheck, lint, build, and security scripts individually and uses the declared/locked package manager. It also recognizes a root Make target, a Cargo repository (`cargo fmt --all --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`, both narrow, then `cargo test --workspace --all-features`) and a basic Python pytest repository. A gate shell script's proposed stages (`init --stages-from-gate`) include its package-script calls, `bash scripts/x.sh` and `cargo ...` steps, and tool execs on a named wrapper line such as `run check pnpm exec biome ci .`.

Checks, analyzer commands, and review runners use an owned process group with bounded capture. Timeout, output-limit, and incomplete-capture results are never passes. The runner drains both streams, allows a termination grace, and stops its capture before returning; processes that deliberately leave the group are outside its termination guarantee. Delegate gets an additional 15 seconds for its own timeout cleanup before its wrapper is stopped. Captured stdout/stderr have a combined 64 MiB limit, and review JSON has an 8 MiB parsing limit, including a separately written output file. Exceeding a limit retains the available evidence and blocks approval.

Native checks retain the repository's normal environment; analyzer/reviewer environments remain restricted. Check names must be unique, and every configured check's shape and timeout is validated before any check executes. Native logs retain separate stdout/stderr files plus the combined log. Existing text/newline/ANSI-normalized failure fingerprints remain comparable; a signal termination is unknown evidence rather than a reusable failed test result.

A failed spawn can name a capture path that was never created. A command reviewer that fails to write its declared output is `invalid_output`; inspect its diagnostic, not just whether a file path was returned.

Review the generated file before trusting a campaign:

```bash
cat .hangover/config.json
```

Commands are JSON argument arrays, never shell strings, with explicit timeouts. Edit this small file when repository discovery is insufficient, especially in monorepos. `hangover init --force` refreshes discovery after backing up the old config.

## Fallow integration

The tool owns and pins `fallow@3.31.0`; target repositories are untouched. Runtime execution fails closed on any other version and never falls back to an ambient PATH binary. `HANGOVER_FALLOW_BIN` is an exact-version test/development override. Rehabilitation scans run focused structured commands:

- `config`
- `dead-code --type-aware` for TypeScript
- `dupes`
- `health --score --complexity --file-scores --hotspots --targets --no-cache`
- `flags --retirement --flag-age off`

CommonJS `.cts` and `.cjs` files participate in source inventory and analyzer selection. When a supported dead-code category's summary count disagrees with its finding records, the section is incomplete: raw evidence is retained, verification cannot pass, and absent records do not make old findings stale. Disabled rules remain explicit policy exclusions, not evidence failures.

Feature flags become one card per flag name. Fallow's retirement report adds code-derived removal reasons. When every workspace's row for a flag has a strong reason (`literal-constant`, `identical-branches`, `empty-branch`, `guards-dead-code`, or `defined-never-read`), it becomes a P2 "Retire feature flag" card with medium confidence; one card covers every workspace's sites. Weaker reasons (`single-read-site`, `test-only`) are added as evidence to the low-confidence inventory card. Flag ages are off so the evidence stays reproducible. The reasons read code only; production flag state still has to be confirmed before removal.

Not adopted: Fallow's opt-in `deprecated-exports-in-use` finding. Its CLI flag selects that section alone, so it would need a separate dead-code run; revisit when a campaign repo has deprecated exports worth migrating.

Prevention runs `audit --base REF`.

Raw stdout, stderr, exit code, resolved-config hash, and tool version are persisted. Exit `0` or `1` means analysis completed; exit `2+` is a tool failure. Findings are normalized only enough to create remediation units. Health complexity findings (per-function cyclomatic, cognitive, and CRAP threshold violators) become backlog items alongside dead-code and duplication; a matching churn×complexity hotspot raises priority one step, capped at P1, and is cited in evidence, but is not itself a backlog item. Fallow's JSON schemas differ by command, so raw documents remain authoritative.

A function is identified by its file and name alone when Fallow's own function listing shows exactly one function of that name in the file and it is the reported one. Fallow reports only functions over their threshold, so one finding does not prove the name is unique; each scan therefore also runs `fallow health --complexity` with every threshold at zero (about half a second on a 13,000-function repo), keeps only positions for the reported names (`function_inventory` in the scan's Fallow result), and trusts it only when it lists exactly as many functions as Fallow says it analyzed. A missing or incomplete listing, or any second function of that name (inline methods and comma-declared arrows included), falls back to the span-anchored identity below. Editing inside it, even shortening it by 100 lines, never makes a new card: the card keeps its history and its metrics are updated (`complexity_metrics`, with a `metrics_changed` history event recording old and new). A function is "introduced" only when it has no card yet, or its card was settled (resolved, stale) and it crosses its threshold again. When `verify` reports introduced findings, it adds one line per card after the summary: `introduced <id>: <title>: cyclomatic A, cognitive B -> cyclomatic C, cognitive D (thresholds X/Y)`, where the old side is the card's last recorded metrics or "below threshold or new". Same-name functions keep span-anchored identities: a hash of the reported source span, so adding unrelated lines above does not change the ID, but editing inside one does. Identical or unavailable spans are explicitly ambiguous. Their IDs include file context and reported location when available, so removing an earlier identical method cannot transfer its disposition to another method. An ambiguous member cannot be verified, or credited as collateral, while same-name findings remain in that file.

Cards from earlier releases (span-anchored, `complexity_identity.version` 2) move to the function key at the next complete scan, by exact evidence only: a card whose recorded source-span hash equals the function's current one, or the only such card for that file and name. Any status migrates, settled cards included, and then follows the normal reopen-on-sight rule; the whole record (status, deferral, history, first_seen) is copied with an `identity_migrated` event and the old record becomes obsolete. Several cards with no exact span match (a stale card is not proof it is the same function: it may be a removed sibling) migrate nothing: the new card opens with an `identity_ambiguous` event naming the candidates. An active (`in_progress`) card must be released first. A scan whose evidence cannot migrate (degraded or incomparable) creates no new-identity card for a finding that has an old card (dead-code, complexity or duplication), so the old ruling is never stranded. Those findings are listed in the scan output and the snapshot (`held_findings`: finding, title, candidate old cards); the old card is neither resolved nor refreshed.

Legacy name-only cards keep their history. Newly anchored cards link back through `identity_from` and start open rather than inheriting an uncertain resolution or deferral. One exception: a deferred legacy card that maps to exactly one anchored function with no card of its own yet passes its deferral and reason to that function (`inherited_from` in the new card's history), because the ruling was about that code. If the anchored card already exists it keeps its own disposition and the legacy card keeps the deferral. A deferred card that splits into several functions was ruled on one member's evidence, so its replacements start open and the legacy card keeps its deferral. Superseded open legacy cards become obsolete, as does a legacy card whose deferral was carried forward; other settled legacy cards keep their recorded disposition. An active legacy identity requires explicit release before its family is migrated: release it, scan, then select the anchored work. Existing fix artifacts are retained. Run scans on a stable tree; verification also rejects input drift during checks or review.

### Dead-code identity

Fallow 3.31 gives every dead-code finding a stable `finding_id` (`dc1:<rule>:<hash>`, from the rule, root-relative path and symbol; a second finding with the same subject gets `~1`). hangover keys dead-code cards by it, so line moves, reformatting and reordering no longer matter; a rename is a new finding. Output without the id keeps the old path-and-symbol key. On rebaseline (or any comparable scan) a card keyed the old way moves to its `finding_id` card by exact match: the full record is copied (status, deferral, history, first_seen) with an `identity_migrated` event, and the old record becomes obsolete. If one old key now maps to several findings (the `~1` case) nothing is inherited: each starts open with `identity_from`, and an open/stale legacy card becomes obsolete while a deferred one keeps its deferral. An active card must be released first.

### Duplication identity and suppression

Duplication cards retain structured instance spans (`duplication_identity`) and
the readable `Instance: file:start-end` evidence. If an analyzer changes a
fingerprint, an exact, unique span-set match to an existing non-terminal card
records a link to its history and inherits only its latest deferral reason.
History stays on the legacy card rather than being copied. Open, reopened, and stale cards carry
forward as open; deferred cards remain deferred, with `inherited_from` naming
the old card. The old card becomes obsolete with `identity_migrated`. An active
card must be released first. Partial matches, splits, and ambiguous matches
start open with an `identity_from` link. A linked open, reopened, or stale
legacy card becomes obsolete; a deferred legacy card keeps its deferral.
Both record `identity_refined` with the replacement IDs, without a one-scan hold.
A card that already has the new fingerprint keeps its own history and ruling.
Distinct groups may share an instance: only their complete span sets establish
identity. Legacy evidence-only cards use the same rule.

Fallow reassigns rank-suffixed fingerprints (`dup:<hash>-rN`) to different clone groups as code changes. When the existing card for such a fingerprint shares no instance with the group now reported, the group gets a fresh card (`reassigned_from` names the old one) instead of reopening the old card with a ruling about unrelated code. The old card keeps its own ruling. A later scan finds the fresh card again only by its complete span set; a group that shares just some instances is new open work linked to the earlier card, like any partial match above, and never takes over its ruling.

Defer for campaign-scoped "not now": `hangover fix ISSUE --defer "reason"`.
Suppress for repo policy, "not ever, and why":
`hangover suppress ISSUE --reason "reason"`. Duplication suppression writes
`duplicates.ignoredClones` in `.fallowrc.json`, using the native key
`<fingerprint>:<instance_count>` (for example, `dup:55572694:2`). It uses the
existing atomic writer, refuses symlinked configs and JSONC rewrites, and
retains unrelated policy. The reason stays in the campaign history. Content
or occurrence-count changes can make the group reportable again; suppressed
cards reopen on sight. Suppression rebaselines Fallow only and records
`checks_inherited_from`, without claiming native checks ran again.

### Analyzer upgrades and evidence limits

After installing this tool's pinned analyzer, run `hangover scan --rebaseline`
on a stable campaign. A version change without that flag is incomparable and
does not change cards. A successful rebaseline migrates identities and records
one `analyzer_upgraded` event with versions, mode, clock epoch, and before/after
status counts in the same locked state revision. A failed or degraded analyzer
run cannot replace the baseline; failure to save the snapshot abandons the
state mutation. Repeating a same-version rebaseline adds no upgrade event.

Fallow 3.31 changes what a rebaseline can show: formatter and linter script targets are no longer entry points (new `unused_files` may appear), boundary checks cover unreachable files, a `!` entry in `ignorePatterns` is now an exception, and `ignoreDependencies` entries with glob characters are globs. hangover calls Fallow's subcommands and already treats exit `0` and `1` as a completed analysis, so the new exit `1` on findings in machine formats for bare `--ci` runs changes nothing here. After the pin changes, run `hangover scan --rebaseline` once per campaign: dead-code cards move to `finding_id` keys and complexity cards to function keys in the same locked revision.

The baseline health artifact records the hotspot clock's epoch, source, and
reproducibility. Later health calls pass that epoch as `FALLOW_CLOCK_EPOCH`;
`--rebaseline` selects a fresh clock. Non-reproducible hotspot evidence is
advisory and cannot raise priority. Health still uses `--no-cache` because a
copied checkout can otherwise inherit path-bound churn data.

Fallow's reachability caveats lower finding confidence. The evidence names
the caveat token and the unread file's diagnostic kind. A file counts as unread
when a workspace diagnostic with a known unread kind or Fallow's
`degrades_analysis` marker names that file or a folder containing it, so
degrading kinds added in later Fallow releases are honored without a hangover
change. A root-level (`.`) diagnostic holds no card; every degrading diagnostic
is summarized in the scan warnings. A run with `no-source-files-analyzed` is incomparable
(`kind: empty_analysis`) and cannot become a rebaseline: an analysis of
nothing cannot stale or obsolete cards. An absent dead-code
finding whose own file was skipped stays open with an `unverifiable`
history event. Unread unrelated files do not hold the card or add diagnostics
to its evidence. Verification checks the union of touched files and the card's
own files; collateral resolution checks the collateral card's own files. `fix --release` reads no
analyzer evidence and remains a membership operation.

Evidence holds never change a card's status: reopened stays reopened and stale
stays stale. Only open/reopened cards receive an `unverifiable` event, and a
matching last event and reason are not appended again. Comparison `kind`
identifies version, mode, config, missing-baseline, and type-aware degradation
cases independently of the human-readable reason. A bare cross-version scan
prints `ledger unchanged` with both versions and the rebaseline command.

Type-aware warnings or incomplete semantic evidence make comparison against
a type-aware baseline incomparable, even when Fallow returns success. One
exception: Fallow reports `partial` when it kept candidates it could not prove
used (for example behind a dynamic import). Such a run is comparable, and can
rebaseline, when it has no warnings, every incomplete query ended in a
`retained-*` decision (the pass removes a candidate only on positive evidence
of use, so nothing is hidden), and api-surface evidence either completed or
is unused because `private-type-leaks` is off. Those retained findings carry
Fallow's reason and low confidence. Such
runs cannot stale or obsolete absent findings. Disabled-rule filtering stays:
explicit repo policy is not a resolution claim. Omitted clone groups or
families, mismatched shown/omitted totals, and missing records mark duplication
evidence incomplete and block verification. Structured analyzer error codes
and help are retained in scan diagnostics.

Fallow is an oracle, not an editor. `fallow fix --yes` is never exposed. Earlier Fallow versions proposed removing required React from a normal Next.js App Router project, and static analysis cannot prove dynamic dispatch, dependency injection, file-system routes, public-package consumers, or runtime registration. Missing `node_modules` downgrades dependency evidence to incomplete; `hangover` never installs target dependencies during a scan.

## Rust integration

Rust support is experimental. Its categories, thresholds and card identities may still change; when they do, hangover's Rust analysis version changes and each campaign needs one `hangover scan --rebaseline` (see "Comparability" below).

A repository with a root `Cargo.toml` gets Rust evidence beside (or instead of) Fallow's. When the workspace lives in a subdirectory, set `root` in `.hangover-rust.json` (below) to that directory. A repository that holds `Cargo.toml` files but none at the analyzed root gets no Rust analysis, and every scan and audit says so on stderr, naming the manifests it found and the `root` value to set (for example `Rust: no root Cargo.toml; found tools/x/Cargo.toml. Rust is not analyzed until .hangover-rust.json names the workspace to analyze`).

Rust cards carry `source: "rust"` and behave like Fallow's: a scan governs them (stale only when the section that reports them completed), `verify` blocks when the original card is still reported or the fix introduced a new one, and `audit --base` gates only what a change introduces. Each scan runs, in `src/hangover/rust.py`:

| Section | Tool | Categories |
|---|---|---|
| `metadata` | `cargo metadata --no-deps` (static mode: the `Cargo.toml` files read as TOML, cargo not run) | the packages, targets and the workspace crate graph (summary `crate_graph`) |
| `items` | ast-grep 0.50.0 (pinned) | the item inventory behind `god_file`, `oversized_module`, `oversized_crate`, `unused_pub_items`, `crate_local_pub`, `wide_pub_surface`; test regions; function names for clippy's spans |
| `clippy` | `cargo clippy --message-format=json --keep-going` with `-W dead_code -W unused_imports -W clippy::cognitive_complexity -W clippy::too_many_lines -W clippy::too_many_arguments` (static mode: `skipped`) | `complexity` (one card per function, all three metrics), `dead_code`, `unused_imports` |
| `dupes` | jscpd 5.4.1 (pinned), Rust tokenizer | `duplication` (clone pairs grouped into clone groups) |
| `machete` | `cargo machete` (optional; `unavailable` when not installed; static mode: `skipped`) | `unused_dependencies` |
| churn | `git log` over the 180 days before HEAD's commit time | top-tier files raise `complexity` and `god_file` priority one level |

What the categories mean:

- `complexity`: clippy's cognitive complexity, lines of code and parameter count, at the policy thresholds (default 15, 100, 7). Priority from the worst ratio to its threshold (≥3× P1, ≥2× P2, else P3); test functions stay P3.
- `dead_code`, `unused_imports`: rustc's own lints, so proven for the targets and features hangover built (`clippy_args`), not for other cfgs.
- `unused_pub_items`: a `pub` item in library code whose name appears nowhere else in the workspace (comments excluded, string contents kept, so a serde `with = "..."` path counts as a use). Items with FFI or framework export attributes (`#[no_mangle]`, `#[napi]`, `#[wasm_bindgen]` and the like) are skipped.
- `crate_local_pub`: one card per crate, listing the `pub` items in its library code that no other workspace crate, binary, integration test or example names. Narrow them to `pub(crate)` together, in one change: one narrowed alone can fail to compile while another `pub` item still exposes it. Narrowing is compile-checked. Only for crates that are not publishable (`publish = false`) and have a workspace consumer.
- `wide_pub_surface`, `god_file`, `oversized_module`, `oversized_crate`: production code size (non-blank, non-comment lines outside `#[cfg(test)]` modules, integration tests and examples) and `pub` counts over the policy thresholds (defaults: 200 exported items, 1000 lines per file, 15000 per directory module, 40000 per crate).
- `duplication`: jscpd clones of at least 100 tokens and 8 lines; the card's identity is a hash of the clone's normalized text, so moving code does not change it. Clones wholly in test code are P3.

Card identities are names and paths, never line numbers: `complexity` is the file plus `Type::function`, lint cards the file plus rustc's message. Clippy runs in its own target directory (`<cargo target dir>/hangover`, or `HANGOVER_CARGO_TARGET_DIR`) with a stable `CLIPPY_CONF_DIR`: a content-named directory under `.hangover/rust-clippy-conf/` holding the analyzed root's `clippy.toml` (or `.clippy.toml`) with hangover's three thresholds in place of the repository's. So hangover's lint flags never invalidate the gate's clippy cache, and a rescan of an unchanged tree replays cached diagnostics in seconds. The first scan of a large workspace is a full `cargo check` of every target.

The analyzers see exactly hangover's file list: the files git lists as tracked, plus untracked files git does not ignore. ast-grep and jscpd are handed each file by path (neither walks a directory, so a file left out of the list, such as a hard link, is never read), with every ignore source off, so a tracked file is analyzed even when a `.gitignore`, `.ignore`, `.git/info/exclude` or `core.excludesFile` pattern matches it. A file list naming a path outside the repository (an absolute path, a `..`, `.` or `.git` component, or a path through a symlinked directory, which only a hand-built index can hold) refuses the scan or audit (exit 2, nothing recorded; see "Files the repository names" under "Trust model").

Repository policy lives in an optional, committed `.hangover-rust.json`; every key is optional and unknown keys are refused:

```json
{
  "root": "rust",
  "clippy_args": ["--workspace", "--all-targets", "--all-features"],
  "thresholds": {"cognitive": 15, "function_lines": 100, "arguments": 7, "file_lines": 1000,
                 "module_lines": 15000, "crate_lines": 40000, "pub_surface": 200,
                 "clone_tokens": 100, "clone_lines": 8},
  "exclude": ["crates/generated/**"],
  "ignore": ["complexity:crates/x/src/parse.rs:Parser::step"]
}
```

`root` is the repository-relative directory whose `Cargo.toml` hangover analyzes (default: the repository root). It must stay inside the repository: an absolute path, a `..` component, a backslash or a symlink on the way is refused. hangover finds that manifest's workspace as cargo does, so a `root` naming a member crate analyzes its whole workspace. An invalid `.hangover-rust.json` makes the Rust scan and the audit `failed`, naming the error; it never passes as "not a Rust repository". The policy file must be a regular file inside the repository: a symlinked, hard-linked or outside one, like a refused `root`, refuses the scan or audit (exit 2).

Waivers: `hangover suppress ISSUE --reason ...` adds the card's key to `ignore` (and rebaselines, as for Fallow). The in-source equivalents also work, since the tools honor them: `#[expect(clippy::too_many_lines, reason = "...")]` (or `allow`) on a function, `// jscpd:ignore-start` / `// jscpd:ignore-end` around a clone, `[package.metadata.cargo-machete] ignored = [...]` in a manifest. `verify --accept` waives an introduced Rust finding exactly as it does a Fallow one.

Comparability: a Rust scan compares with the baseline only when hangover's Rust analysis version, every tool version (cargo, clippy, ast-grep, jscpd, cargo-machete), the policy file and the set of available sections are unchanged; otherwise `verify` blocks with `run hangover scan --rebaseline`. Installing cargo-machete mid-campaign is such a change, and so is moving between static and executing scans (static scans lack the clippy and machete sections). The analysis version is now 2 (`crate_local_pub` became one card per crate instead of one per file), so a campaign recorded under version 1 needs one `hangover scan --rebaseline`; the per-file cards are no longer reported after it. A compile error, or any error-level diagnostic in a library target (cargo then never checks the crates that depend on it), makes the clippy section `partial`: verify cannot pass on that scan and no clippy card goes stale. An error-level lint in a test, binary or example target (clippy's `never_loop`, say) blocks nothing downstream; it is listed as a warning for the gate to deal with, not as a hangover finding.

`audit --base REF` writes the base commit's files from git objects into hangover's own directory, `.hangover/rust-audit/tree`, analyzes them, and fails on any card the working tree has that the base does not. Nothing is checked out (`git ls-tree` and `git cat-file --batch` only), so no hook or filter runs, and git is never run inside the tree. The tree is kept between audits and synced in place, so a file the base did not change keeps its mtime and cargo stays incremental; it shares this tree's hangover target directory. The first audit of a large workspace compiles its crates once more under that path. hangover refuses, and never reuses or removes, a `.hangover/rust-audit/tree` it did not create (a symlink, a directory without its owner marker, or files the repository tracks there). Earlier versions kept the base in a git worktree at `.hangover/rust-audit-base`; this version leaves it alone and names it in a warning with the `git worktree remove --force` command that removes it.

Building the base tree runs its build scripts (audit always executes; see "Trust model"). They run with git discovery stopped at the tree (`GIT_CEILING_DIRECTORIES`), so a build script that calls `git rev-parse` or `git describe` finds no repository and takes its no-git fallback, as for a crate downloaded from a registry, instead of reading the checkout's HEAD. A build script that opens `../.git` by path still reaches the checkout; nothing short of a separate clone prevents that.

On a case-insensitive or Unicode-normalizing volume (the macOS default), two names in the base commit that differ only by case or normalization are one directory entry. The audit then fails, naming both, rather than analyzing a tree that is not the commit: audit from a clone on a case-sensitive volume.

A mixed repository (a TypeScript gate driving cargo, say) can turn Fallow off for a Rust-only campaign with `"fallow": {"enabled": false}` in `.hangover/config.json`, and `"rust": {"enabled": false}` does the reverse.

Known limits: the `pub` analysis is textual, so a name built by a macro or generated by a build script can look unused (the compiler then rejects the deletion, so the gate is the backstop); cargo-machete reads source text and misses dependencies used only through features or macros; `#[cfg]`-gated code outside the built feature set is invisible to rustc's dead-code lint; only the analyzed root's `clippy.toml` is merged into hangover's clippy configuration. Static mode has no compiler evidence at all (no `complexity`, `dead_code`, `unused_imports` or `unused_dependencies` cards), and its workspace reader follows cargo's rules for members, excludes, path dependencies and inherited fields but never looks above the repository root. Static mode needs git 2.42 or newer; executing Rust scans accept older git.

## Fresh-context review

### Reviewer contract

- runs in a genuinely fresh context;
- returns schema-constrained JSON (`schemas/review.schema.json`);
- sees no prior verdicts or backlog;
- treats target files, instructions, and captured evidence as untrusted input, not authority.

A post-fix review fails only for a behavior or test regression, insufficient evidence to judge the change itself, an untracked finding introduced by the change, or an unresolved deletion fence; a pre-existing coverage gap the diff does not widen is a non-blocking follow-up.

Every post-fix review must echo its packet's `verification_token`, whichever route delivered it, automated runners included. A verdict with no token, or another attempt's token, cannot close the remediation, so a stale, cached or packet-blind reviewer output is refused. Only a `pass` verdict approves: `fail` or `partial` blocks the remediation (exit 1), and the output names the verdict and the reviewer's summary.

A nonzero runner exit, a missing `reviewed_files` list, or an empty list with no findings is unknown evidence. It produces `tool_error`, exits nonzero, and never supplies fresh review approval. A passing verdict requires at least one inspected file. The summary can describe unavailable dynamic checks alongside completed source inspection; its wording alone does not reject a verdict.

Automatic subjective deduplication requires the same source, parent remediation, category, file and symbol scope, and the same nonempty harm, proposed change, and invariants. A title may be reworded when symbols provide an anchor. Without symbols, the title must also match. Overlap alone creates a `possible_duplicates` link while preserving the new finding, its scope, and its priority.

Real merges union evidence and verification suggestions, keep the higher severity and risk, and retain the lower confidence when reviewers disagree. Alternate claims and displaced scalar values remain in `seen_again` history. A contradictory claim sharing an older coarse fingerprint receives a refined ID rather than overwriting the earlier issue. `hangover dedupe` uses the same rules; its JSON pairs distinguish `same_remediation` from `overlap_only`, and `--apply` closes only the former after transferring evidence. Reviewers are still never shown the prior backlog.

Uncertain rewordings link to prior dispositions, including resolved, suppressed, and deferred issues, rather than silently overruling them. Re-imported closed duplicates follow their recorded canonical relation only while the claims still match. An unsupported old coarse alias reopens as its own issue. An exact deferred match keeps its disposition even when another open issue looks similar.

A finding you decide not to fix has explicit disposition tiers, each requiring a recorded reason. `hangover verify --accept` waives a single introduced finding for one remediation. `hangover suppress` makes it repo policy: when a Fallow finding carries a config-keyed remedy (Fallow's own `add-to-config` action, such as adding a package to `ignoreDependencies`), the command applies that edit to the target repo's `.fallowrc.json` and marks the issue `suppressed`. It creates the file if absent and refuses to rewrite a commented `.fallowrc.jsonc`. Because the edit lives in the repo's own Fallow config, direct `fallow` runs and hangover scans agree. Disabling a whole rule is Fallow's own severity config (`rules` in `.fallowrc.json`), edited by hand. A suppressed finding that a later scan still reports is reopened, exactly like a resolved one, so an ineffective suppression cannot hide.

Review findings become `obsolete` when a full scan finds that every referenced file is gone; for a partial removal, use `hangover fix ISSUE --obsolete "reason"` (Fallow findings remain scan-governed).

The execution boundary depends on the runner, and hangover implements no sandbox of its own. The `codex` runner invokes Codex CLI with `-s read-only`, and the `delegate` runner asks the delegate CLI for its lane's read-only (`safe`) mode; in both cases the read-only guarantee is the invoked tool's and holds exactly as far as that tool enforces it. The `command` runner is a trusted unsandboxed subprocess, in the same trust class as native checks; operators who need read-only enforcement must supply their own read-only wrapper.

Delegate and command runner CLIs that need ambient environment, such as credential or profile selection and proxy settings, can receive named variables through `review.env`. New configs start with an empty list; add only what your runner needs. Keep the list minimal: config stores names only, and values come from the invoking environment. `HOME`, `PATH`, `SHELL`, and any `GIT_*` name are refused, because the review environment pins them so a repository config cannot make a reviewer resolve a different binary or reconfigure Git.

Initial and post-fix adversarial reviews use the same contract. The post-fix prompt adds the relevant diff, invariants, native before/after results, Fallow evidence, and repository constraints.

### Codex runner

`codex` is the recommended default. Its invocation, abbreviated:

```bash
codex exec --ephemeral --ignore-user-config -c project_doc_max_bytes=0 \
  -c shell_environment_policy.inherit=none ... -s read-only --add-dir TARGET \
  --output-schema schemas/review.schema.json -o RUN/review.json -C TEMPDIR --skip-git-repo-check -
```

It runs from a temporary directory outside the target, with project instruction files disabled and user config ignored; the shell commands Codex runs get a run-local `HOME` and none of the inherited environment. The prompt arrives on stdin.

### Delegate runner

`delegate` is a separate operator-installed command-line tool that runs one prompt through a chosen model back end, called a lane; hangover only shells out to it and never bundles it. Set `review.runner` to `delegate` to route reviews through it. If you use delegate, any model it exposes can review. Configure its lane, optional model, and optional reasoning effort in `.hangover/config.json`; `--lane`, `--model`, and `--reasoning-effort` override those values on `hangover review` and `hangover verify`.

For lanes without harness-level schema enforcement, hangover embeds the schema in the prompt and validates the returned JSON. Set `HANGOVER_DELEGATE_BIN` to an exact delegate binary path, just as `HANGOVER_CODEX_BIN` overrides Codex.

Because a lane need not share a filesystem with hangover, the delegate prompt inlines the review packet and any before/after patches instead of pointing at them. File paths recorded inside the packet, such as raw Fallow artifacts, are therefore not readable from the reviewer's context; only the inlined content is available to it.

### Command runner

Set `review.runner` to `command` and `review.command` to an argv array for a bring-your-own reviewer. The command runs with the target repository as its working directory; hangover captures stdout/stderr and validates the resulting JSON. Placeholders replace a whole argument only, never a substring:

| Placeholder | Substituted value |
|---|---|
| `{prompt}` | Generated review prompt path. |
| `{output}` | Review JSON output path. |
| `{repo}` | Target repository path. |
| `{schema}` | Review schema path. |

If the template contains `{prompt}`, hangover passes the generated prompt file path and does not send the prompt on stdin. If it omits `{prompt}`, hangover sends the prompt on stdin instead. If the template omits `{output}`, hangover parses stdout as the review JSON. A command that exits successfully but emits invalid JSON is still an invalid review.

## Review configuration

The generated config includes all runner keys and remains backward-compatible with older config files:

```json
"review": {
  "runner": "codex",
  "timeout_seconds": 1200,
  "delegate": {"lane": "codex", "model": null, "reasoning_effort": null},
  "env": [],
  "command": null
}
```

## Review fallbacks

Before spending a repository gate, `run` and `verify` resolve the requested review route and check it offline. Command reviewers are checked for an executable path without running repository code. Codex checks local login status and runs a trivial command through its read-only sandbox without a model; Delegate uses a bounded safe-mode dry-run to check its profile, transport, and requested selection without invoking a model. Neither check proves credentials are valid online. The resolved route is held for that invocation, so a config edit during checks cannot silently switch its reviewer. Requested and resolved selections are retained in `review-run.json`.

Codex sandbox startup errors explain failed reviews as a runner environment failure. Diagnostics do not veto a valid completed verdict, and echoed prompt/model content is excluded. If bwrap or Codex runtime writes are denied, use `--runner delegate --lane claude`, or run outside the confining sandbox. Landlock write policies and container sandboxes can block bwrap. Startup probes use an isolated config directory to exclude user config, matching the review's `--ignore-user-config` policy.

`--no-review` skips review readiness, and manual prepare/import does not require an installed reviewer. Invalid option combinations and timeouts are still refused before review artifacts are created.

If an automated reviewer fails, choose an explicit alternative. For example, the
command below selects Claude rather than retrying Codex. The delegate lane defaults
to `codex`; omitting `--lane` does not change families.

```bash
hangover review --runner delegate --lane claude
```

If no runner works, keep the packet and run it in a genuinely fresh, read-only context:

```bash
hangover review --prepare
# Run the packet in a separate read-only context using schemas/review.schema.json.
hangover review --import /path/to/review.json
```

For a remediation, run `hangover verify --issue ISSUE --runner none` first. It runs the gates and prepares a post-fix packet with a `verification_token`. A fresh, read-only reviewer must echo that token in its JSON. Import with `hangover review --issue ISSUE --import /path/to/review.json`. Keep the review output outside product source, either under `.hangover/` or outside the repository.

Prepared reviews print the packet, prompt, run-local schema, verification token (for a remediation), expected output path, and exact repository-qualified import command. Have a separate read-only reviewer follow the printed prompt and write its verdict before running that command. `review --prepare --json` and `verify --runner none --json` include the same paths and token under `data.review`.

A failed remediation runner's own verdict file is retained for diagnosis and refused as an import, including through symlinks and hardlinks. A fresh reviewer must write a separate artifact, such as `manual-review.json`, carrying the pending token. This file check prevents accidental reuse; it does not prove reviewer identity.

The issue stays in progress until review passes. `verify --no-review` records deterministic evidence without preparing a review; `review --issue ISSUE --prepare` can then prepare one from that evidence. Older campaigns need a new verification before post-fix review can close them. Existing artifacts and dispositions are preserved.

### What a verification binds

Each verification has its own before/after patches, snapshot, native-check logs, and analyzer artifacts. Closure checks their hashes and the remediation attempt, member set, notes, waivers, baseline, check policy, analyzer config, and verifier inputs. Tracked and non-ignored untracked working-tree content must still match after checks and after review. A new verification invalidates the previous proof before running any checks, even if the new run fails. A passing import consumes its token in the same state update that resolves the batch; an unrelated scan does not replace that import's evidence.

Updating Hangover's verifier code, schema, or post-fix prompt invalidates pending proofs in existing campaigns; run verification again with the updated tool.

Implementer notes receive stable IDs. A passing review must assess each issued note once, reference its ID in `note_id`, and cite evidence. Missing, duplicate, unrelated, or rejected assessments cannot close a remediation. Legacy notes receive IDs on the next explicit verification; their text and history remain intact.

Staging or committing unchanged working-tree content does not invalidate the proof. HEAD is recorded as provenance, not as content identity. This is not a staged-commit or Git-history proof. Ignored dependencies, external services, arbitrary command environments, and transitive tool installations are not frozen. Hash checks detect drift at execution boundaries; they do not defend against a hostile concurrent writer changing inputs and changing them back. A protected merge policy must own any stronger enforcement boundary.

## Persisted state

```text
.hangover/
├── config.json             # discovered, editable commands and runner settings
├── state.json              # canonical backlog, status, history, baseline pointers
├── gate-proofs.json        # reusable passing gates, keyed by exact tree (see "Gate cost")
├── fixes/<issue>/<time>/   # original fix packet, before patch, notes
├── runs/<run-id>/          # snapshots, raw analyzer JSON, logs, review packets (bounded; see below)
├── rust-clippy-conf/       # generated clippy configuration, one content-named directory each
└── rust-audit/tree/        # the base commit's files for Rust audits, written from git objects
```

Run directories are written once and never edited, but `.hangover/runs/` is bounded. Each time a command creates a run it removes older ones, keeping: the newest 10; every run the campaign still references (the baseline and latest scan, review and audit, open remediation proofs and their prepared review packets, prepared initial reviews until they are imported or superseded, unconsumed audit proofs, recorded reusable gates, and the runs whose check logs a kept run inherited, followed transitively); and every run a live hangover process is still writing, which holds an `flock` lease on the run's `.lease` file for as long as it runs. A crashed process's lease is released by the OS, so its run becomes ordinary history. `fixes/` is not pruned.

`hangover init` creates `.hangover/` with user-only directory permissions and adds `/.hangover/` and `/.fallow/` to the repository's local `.git/info/exclude` (only the checkout's own: in a linked worktree or submodule, whose exclude file belongs to another checkout, nothing is written); it does not edit the committed `.gitignore`. It also writes the owner marker `.hangover/owner` that static mode checks (see "State the checkout ships" under "Trust model"). Each `review-run.json` records the selected `runner` alongside the review result. Logs, patches, and analyzer output can contain source or secrets printed by repository commands, so keep this directory private and untracked. Delete those local directories to discard campaign/analyzer caches. Do not commit `.hangover/`: every command but `hangover fallow` refuses a repository that tracks files there, since tracked state could choose hangover's checks and review command.

The active remediation owns shared evidence once; per-issue fields remain compatibility views. Completed attempts remain archived. Malformed active state is refused without discarding history. `init --force` refreshes config and is not a state-repair command; its one state change is rebinding a campaign whose checkout moved or was copied (the state records its repository path, and the old path is kept in history).

## Safety model

- Preserve behavior over cleanliness.
- Investigate public APIs, routes, reflection, DI, plugins, generated files, schemas, migrations, environment variables, serialization, CI, and deployment before deletion.
- Never weaken types, lint, tests, security, or analyzer configuration to produce a better result.
- Never auto-suppress findings.
- Keep remediation batches coherent and small; avoid broad formatting churn.
- Compare Fallow metrics only under the same version and resolved configuration.
- Treat an analyzer score as directional evidence, not a target.
- Reopen a supposedly resolved deterministic finding when a later scan sees it again.
- Refuse symlinked state paths, and any repository-named file or listed path that is absolute, has `..`, passes through a symlink, is a hard link or resolves outside the repository, rather than reading or writing outside the target repository (see "Files the repository names").
- Disable repository fsmonitor/external-diff execution for harness-controlled Git reads, and in static mode every repository-configured git driver (see "Trust model"); omit analyzer state and secret-looking untracked files from review patches.

## Limitations

- Deterministic structural analysis is deepest for TypeScript/JavaScript (Fallow). Rust Cargo workspaces get the experimental Rust analysis. Other languages receive repository inventory, native checks, persistent backlog, and subjective review, but no dead-code/duplication oracle; `scan`, `run`, `status`, `next` and `audit` say which source files no deterministic analyzer covered. Static mode adds nothing for TypeScript/JavaScript (Fallow does not run there) and only the source-level part of the Rust analysis.
- A repository whose gate script or manifests live outside it, or reach it through symlinks or hard links, is refused in every mode (see "Files the repository names").
- Root-script discovery is intentionally shallow. Configure monorepo package checks explicitly.
- Baseline comparison classifies failures by command outcome, not semantic equivalence of every diagnostic line.
- Fresh context decorrelates rationale, not model-family blind spots. With delegate configured, a different-family reviewer is a one-flag choice via `--lane` or `--model` for a risky post-fix review.
- Audit mode requires Git.
- No security scanner is invented; existing repo-native security commands are reused.
- Native checks and Rust builds are arbitrary repository code, and automated review sends inspected code/evidence to the configured model provider. Do not use those modes on an untrusted or confidentiality-restricted checkout; static mode is the only one meant for an untrusted checkout, and it is not a sandbox.
- Windows is not supported.
- Captured command output is not secret-redacted. `.hangover/` is private and locally ignored, but repository checks should avoid printing credentials.

## Update and uninstall

### Update

An npm install updates by installing again from the same source:

```bash
npm install -g git+https://github.com/treygoff24/agent-hangover.git    # or the new tarball
hangover doctor
```

A clone updates in place:

```bash
git pull --ff-only
npm ci
hangover doctor
```

A new hangover version can change verifier code, prompts or the Rust analysis version: finish or re-run pending verifications afterwards, and run `hangover scan --rebaseline` when a scan says the baseline is not comparable. A campaign created before the owner marker existed needs `hangover init` once before `--no-checks` will use it (see "State the checkout ships").

### Uninstall

An npm install:

```bash
npm uninstall -g agent-hangover
rm ~/.claude/skills/hangover          # if you linked the skill
```

A clone: remove the links you created, for example:

```bash
rm ~/.local/bin/hangover
rm ~/.claude/skills/hangover
```

Then remove the clone if desired. Existing `.hangover/` campaign state remains readable JSON.

## Security

hangover's job is to read checkouts you may not trust, so a way for a repository to make hangover read outside itself, run its code in static mode, or choose hangover's checks or reviewer is a security bug. Please report one privately through GitHub's security advisories on this repository (the "Report a vulnerability" button under its Security tab) rather than in a public issue. Include the hangover version (`hangover doctor`), the command, and a minimal checkout that reproduces it.

What hangover does and does not promise is in "Trust model": executing mode runs repository code by design, and static mode is not a sandbox.

## Extending without making a framework

Do not add a plugin system preemptively. Add one focused subprocess adapter only when a real language/tool has structured output, a tested failure contract, and a repository that needs it. Keep campaign state, verification, and review schemas stable; keep tool-specific raw output opaque.

## Development

```bash
npm ci
npm run check
```

The test suite uses only Python's standard library and disposable Git repositories. The Rust tests build small Cargo fixtures under `tests/fixtures/rust/` and are skipped where cargo, ast-grep or jscpd (from `npm ci`) is missing; a few process tests run only on macOS. Running hangover on its own checkout prints the Rust manifest notice for those fixtures, which is expected: the repository has no root `Cargo.toml`.
