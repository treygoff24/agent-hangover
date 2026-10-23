# Running a campaign

This is the long form of the workflow in the [README](../README.md): how a fix batch moves from `fix` to `verify`, how `audit` gates new work, what `verify` spends on the repository's gate, how several worktrees share one campaign, and how hangover finds a repository's checks. Flags for every command are in the [command reference](reference.md).

Words used throughout:

- **campaign**: one repository's cleanup effort, kept in `.hangover/` across sessions;
- **gate**: the repository's own checks (tests, types, lint, build), discovered by `hangover init` and stored in `.hangover/config.json`;
- **card** (or issue): one backlog item, from an analyzer finding or a review finding, with an ID such as `hang-9a2d94daa6`;
- **batch**: the cards one fix covers, locked by `hangover fix`;
- **fix packet**: the JSON `hangover fix` prints, with each card's evidence, the behavior that must not change (its invariants), and how to verify;
- **fresh review**: a separate model run that sees only the diff and the evidence, never earlier verdicts.

## The fix loop

```bash
hangover run
hangover status
hangover next
hangover fix hang-0123456789 [hang-9876543210 ...]

# You (or your agent) read the fix packet, find out why the code exists before
# removing it, edit one coherent batch, and run narrow checks while working.

hangover verify --issue hang-0123456789
hangover next
```

`hangover fix` deliberately does not mutate product code. It locks one coherent batch, captures the pre-edit patch, and emits the fix packet (evidence and invariants) for the person or agent making the edit. `hangover verify` runs the deterministic evidence (cheap first, see [Gate cost](#gate-cost)) and a separate adversarial reviewer once; it resolves every item in the batch only when both pass.

Select only the issues you intend to fix. If a batch is too broad, release named
members without deferring the rest:

```bash
hangover fix --release hang-9876543210
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
credit. A wider selection leaves additional files explicitly unreviewed. A stored
verdict without `reviewed_files` gets no coverage credit, and imports must include it;
the schema-producing runners do. Counts and a coverage-artifact path
are returned in JSON; the full manifest is retained separately. Coverage is
self-reported and never an exhaustive or clean-codebase claim.

Leave risky work explicit with a recorded reason, rather than treating it as
completed:

```bash
hangover fix hang-0123456789 --defer "Dynamic plugin registration has no safe local parity test"
```

## Gating new changes with audit

For uncommitted work:

```bash
hangover audit --base HEAD
```

Before merge:

```bash
git fetch origin main
hangover audit --base origin/main
```

Audit mode runs `git diff --check` (including untracked text files), Fallow's changed-code `audit`, and discovered lint/type/security commands; when none of those exist (for example, only a combined `verify` gate was discovered), it runs every configured check and says so. Fallow labels introduced versus inherited findings and gates only introduced debt. For a Cargo workspace it also runs the Rust analysis on this tree and on the base commit and fails on any Rust card the base does not have (see [Rust integration](analyzers.md#rust-integration)). Add `--full` to run every configured native check.

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

## Gate cost

The configured gate can take many minutes, so verify spends it last and at most once per tree.

- **Cheap evidence first.** `verify` runs `git diff --check`, the Fallow scan and the introduced-findings check (with `--accept`) before any native check. If one of them blocks, the gate does not run and the snapshot records `gate: not_run`.
- **Dead-code queries.** Verify asks Fallow about each dead-code batch member that has disappeared, after the other cheap evidence passes. Member-specific unknowns block; repo-wide limits are `not_applicable`. Fingerprints are audit data. Queries mirror scan mode and retry syntactically after type-aware failure. Gate and review remain required.
- **Stages.** `hangover init` splits a combined gate into ordered stages only in one case: a package.json script that is a pure `&&` chain where every element is a package-script invocation through the package manager (`npm run x`, `npm test`, `pnpm x`, `pnpm run x`, `yarn x`, `yarn run x`, `bun run x`) naming a script that exists, with no `pre`/`post` npm hooks on the combined script. Tokens are kept exactly (`npm test` stays `npm test`) and the declared order is kept. Anything else (a direct command such as `node check.js` or `tsc`, an env prefix, shell syntax, a gate shell script) stays one check (`verify`). Auto-split stages carry the script they came from and a hash of its definition; `verify` re-reads the gate first, and if it changed since init it re-discovers the stages, updates `.hangover/config.json`, says so, and records it in the snapshot. Run `hangover scan --rebaseline --checks` afterwards. Checks without `stage_of`/`adopted_from` are explicit configuration you own; hangover never rewrites them.
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

- A second batch can be open only when it names its branch; a card is in at most one open batch. `hangover status` lists every open batch. `fix <primary>` on a parked batch makes it the one that `verify`, `review` and `release` act on.
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
