# Command reference

Every command, its exit codes, the JSON interface agents should drive, and what hangover keeps on disk. `hangover <command> --help` prints the flags for one command.

Global options go before the command:

- `--repo PATH` targets a repository other than the current directory (`hangover --repo /abs/path status`);
- `--quiet` suppresses live progress lines on stderr;
- `--version` prints the version.

## Commands

| Command | Purpose |
|---|---|
| `hangover init [--force] [--stages-from-gate]` | Discover checks and create `.hangover/` state. `--stages-from-gate` adopts the commands of a gate shell script as explicit ordered checks (see [Gate cost](workflow.md#gate-cost)). |
| `hangover scan [--checks \| --no-checks] [--rebaseline]` | Capture analyzer evidence (Fallow, and Rust for a Cargo workspace) and compare it with the original baseline. Analyzers only by default (for Rust that still runs cargo, so build scripts run); `--checks` also runs the configured checks; `--no-checks` is static mode (no checks, no Fallow, Rust without cargo; regular clones only; see [Trust model](trust-model.md)). `scan --rebaseline --checks` records which stages are red; `scan --rebaseline --no-checks` is blocked. |
| `hangover status [--json] [--stale]` | Show campaign runs, issue counts, and the next item; `--stale` lists both stale and obsolete terminal issues. |
| `hangover next [--json]` | Resume active work or select the highest-priority open remediation. |
| `hangover list [--json] [--source SOURCE] [--category CATEGORY] [--status STATUS] [--file PATH] [--group-by dir\|file\|category] [--sort lines] [--exclude-tests]` | Filter concise issue records; each filter is repeatable. `--group-by` summarizes findings (dir adds source-line counts), `--sort lines` orders by duplicated-line weight, `--exclude-tests` drops tests/spikes/docs/fixtures by path convention. A finding touching several directories or files counts its full weight in each group, so group totals are not additive; directory source-line counts include test files even with `--exclude-tests`. `status` also prints a recorded baseline-to-latest delta line. |
| `hangover preview [ISSUE ...] [--limit N] [--json]` | Inspect candidate members, shared files, overlap, and outliers without activating work. |
| `hangover review [--scope PATH ...] [--runner {codex,delegate,command,none}] [--lane LANE] [--model MODEL] [--reasoning-effort EFFORT] [--json]` | Run a fresh initial review of the repository with the configured or selected runner. `--scope` (repeatable) limits it to files or directories. `--issue ISSUE` reviews an in-progress remediation instead. |
| `hangover review --prepare` | Write a packet without invoking a runner. |
| `hangover review [--issue ISSUE] --import FILE` | Import schema-conforming review JSON written by a reviewer you ran yourself. |
| `hangover dedupe [--apply] [--json]` | Report duplicate candidates; `--apply` merges only same-remediation matches and leaves overlap-only suggestions open. |
| `hangover fix [ISSUE ...] [--json]` | Start one coherent remediation batch or resume an open batch's primary without resetting evidence. `--branch NAME` records the batch against a branch and lets it be open beside another batch; `fix PRIMARY ID... --add` adds cards to an open batch under the same membership rules. See [Campaigns with parallel worktrees](workflow.md#campaigns-with-parallel-worktrees). |
| `hangover packet ISSUE... [--out FILE [--force]] [--json]` | Write a fix packet for a set of cards without activating anything; stdout by default. `--out` refuses anything inside a `.hangover` or git directory (symlinks followed) and an existing file unless `--force`. |
| `hangover fallow -- ARGS` | Run the pinned Fallow in this checkout (`--root` set, same environment as hangover's scans), so a worktree lane sees exact clone spans and the like. Read-only: analysis and inspection commands only; `fix`, `init`, `migrate`, `hooks`, `watch` and the like, write flags (`--yes`, `--save-*`, `-o/--output-file`, `--sarif-file`) and `--root` overrides are refused. |
| `hangover verify --issue ISSUE [--runner {codex,delegate,command,none}] [--lane LANE] [--model MODEL] [--reasoning-effort EFFORT] [--accept FINDING_ID --accept-reason REASON] [--merged \| --all] [--model-only]` | Re-run the analyzers and the gate, adversarially review, and resolve on success; `--accept` waives an introduced finding already tracked as its own issue. `--affected` runs the analyzers plus only the checks marked narrow and records a partial proof that resolves nothing. `--fresh-gate` ignores a reusable gate proof. `--merged` verifies every open batch whose branch is merged into HEAD, `--all` every open batch, with one cheap phase and one gate run. See [Gate cost](workflow.md#gate-cost). With no configured checks, verify refuses to resolve anything unless you pass `--model-only`: the analyzers and the model review alone then decide, and the proof is labelled model-only wherever it is shown. `--model-only` is refused when checks are configured. `--no-review` records the deterministic proof without a review; `--retry-review` reruns only the review on an unchanged proof; `--note TEXT` and `--note-file PATH` (repeatable) give the reviewer implementer notes it must assess. |
| `hangover suppress ISSUE --reason REASON [--no-rebaseline]` | Apply the finding's Fallow config remedy (e.g. `ignoreDependencies`) to the target repo's `.fallowrc.json` (a Rust finding: its key to `ignore` in `.hangover-rust.json`) and mark the issue suppressed. |
| `hangover run [--no-checks] [--no-review] [--runner {codex,delegate,command,none}]` | Initialize, scan, review, and select the next item. `--no-checks` is static mode (no checks, no Fallow, Rust without cargo; regular clones only; see [Trust model](trust-model.md)); `--runner` picks the reviewer for this run (`none` prepares the packet without invoking one). |
| `hangover audit --base REF [--full] [--json] [--require-review [--prepare \| --import FILE] [--runner ...]]` | Gate only what a change introduces, not debt the repository already had. `--full` runs every configured check; `--require-review` also demands a fresh review of the whole change. See [Gating new changes with audit](workflow.md#gating-new-changes-with-audit). |
| `hangover doctor [--json]` | Report the Python, Node, Fallow and Rust tool versions and Codex/delegate presence; test Codex's read-only sandbox without a model, or dry-run the configured delegate route. The delegate Codex lane also probes a local Codex binary when available. A configured `command` reviewer is reported as a resolved path and never executed. Rust tool versions are probed outside the checkout, so its `rust-toolchain.toml` is not consulted. Exits 1 when something required is missing; `--json` prints the report as one object (`tools`, `missing`, reviewer readiness). |

`status`, `next`, `list`, `preview` and `packet` also take `--state-from PATH` to read the campaign of a main checkout from a linked worktree.

## Exit codes

| Exit | Meaning |
|---|---|
| `0` | The operation completed. Its JSON `state` is one of `ready`, `in_progress`, `review_pending`, `resolved`, `passed` or `no_open_work`; `0` alone does not mean an item resolved. `scan` and `run` exit 0 once they have recorded a scan, so read their printed status for an analyzer that failed (a static scan's `skipped` Fallow is not a failure). |
| `1` | A verdict blocked it (`state: blocked`): a new or changed gate failure in `verify`, an introduced finding, a failed check or `git diff --check` in `audit`, or a post-fix review whose verdict is `fail` or `partial` (from `verify`, or from `review --issue ... --import`). Also: `doctor` found something required missing, `init --stages-from-gate` adopted nothing, or `suppress` could not verify its rebaseline. |
| `2` | Evidence or execution failed (`state: tool_error`): an analyzer that did not complete in `audit`, a reviewer that failed or returned invalid output, a filesystem error, invalid arguments, or a `scan --rebaseline` whose reset was blocked. Also every security refusal, from whichever command meets it (`init`, `scan`, `run`, `verify`, `audit`, `doctor`, `suppress` and the rest): a file the repository names that breaks the containment rule, a refused git file list, a tracked or (in static mode) unowned `.hangover/`, and in static mode a git location that is not a regular clone, a git config with includes, or a git command past its deadline. A refused scan is never saved as the baseline or latest run, and `status` exits 2 while the last scan stands refused. |

Historical baseline failures do not become regressions merely because they remain red.

## Driving the tool with JSON

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

## Persisted state

```text
.hangover/
├── config.json             # discovered, editable commands and runner settings
├── state.json              # canonical backlog, status, history, baseline pointers
├── gate-proofs.json        # reusable passing gates, keyed by exact tree (see "Gate cost" in workflow.md)
├── fixes/<issue>/<time>/   # original fix packet, before patch, notes
├── runs/<run-id>/          # snapshots, raw analyzer JSON, logs, review packets (bounded; see below)
├── rust-clippy-conf/       # generated clippy configuration, one content-named directory each
└── rust-audit/tree/        # the base commit's files for Rust audits, written from git objects
```

Run directories are written once and never edited, but `.hangover/runs/` is bounded. Each time a command creates a run it removes older ones, keeping: the newest 10; every run the campaign still references (the baseline and latest scan, review and audit, open remediation proofs and their prepared review packets, prepared initial reviews until they are imported or superseded, unconsumed audit proofs, recorded reusable gates, and the runs whose check logs a kept run inherited, followed transitively); and every run a live hangover process is still writing, which holds an `flock` lease on the run's `.lease` file for as long as it runs. A crashed process's lease is released by the OS, so its run becomes ordinary history. `fixes/` is not pruned.

`hangover init` creates `.hangover/` with user-only directory permissions and adds `/.hangover/` and `/.fallow/` to the repository's local `.git/info/exclude` (only the checkout's own: in a linked worktree or submodule, whose exclude file belongs to another checkout, nothing is written); it does not edit the committed `.gitignore`. It also writes the owner marker `.hangover/owner` that static mode checks (see [State the checkout ships](trust-model.md#state-the-checkout-ships)). Each `review-run.json` records the selected `runner` alongside the review result. Logs, patches, and analyzer output can contain source or secrets printed by repository commands, so keep this directory private and untracked. Delete those local directories to discard campaign/analyzer caches. Do not commit `.hangover/`: every command but `hangover fallow` refuses a repository that tracks files there, since tracked state could choose hangover's checks and review command.

The active remediation owns shared evidence once; per-issue fields remain compatibility views. Completed attempts remain archived. Malformed active state is refused without discarding history. `init --force` refreshes config and is not a state-repair command; its one state change is rebinding a campaign whose checkout moved or was copied (the state records its repository path, and the old path is kept in history).
