# Analyzers

What the deterministic analyzers report, how their findings become backlog cards, and how a card keeps its identity as code moves. hangover runs Fallow for TypeScript and JavaScript and an experimental set of tools for Rust Cargo workspaces; other languages get native checks and model review only.

## Fallow integration

hangover owns and pins `fallow@3.31.0`; target repositories are untouched. Runtime execution fails closed on any other version and never falls back to an ambient PATH binary. `HANGOVER_FALLOW_BIN` is an exact-version test/development override. Rehabilitation scans run focused structured commands:

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

### Dead-code identity

Fallow 3.31 gives every dead-code finding a stable `finding_id` (`dc1:<rule>:<hash>`, from the rule, root-relative path and symbol; a second finding with the same subject gets `~1`). hangover keys dead-code cards by it, so line moves, reformatting and reordering do not matter; a rename is a new finding. Output without the id keeps the old path-and-symbol key. If a later scan does report ids, a card keyed the old way moves to its `finding_id` card by exact match (the full record is copied with an `identity_migrated` event, and the old record becomes obsolete); when one old key maps to several findings, nothing is inherited and each starts open with an `identity_from` link.

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

Rust support is experimental. Its categories, thresholds and card identities may still change; when they do, hangover's Rust analysis version changes and each campaign needs one `hangover scan --rebaseline` (see Comparability below).

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

The analyzers see exactly hangover's file list: the files git lists as tracked, plus untracked files git does not ignore. ast-grep and jscpd are handed each file by path (neither walks a directory, so a file left out of the list, such as a hard link, is never read), with every ignore source off, so a tracked file is analyzed even when a `.gitignore`, `.ignore`, `.git/info/exclude` or `core.excludesFile` pattern matches it. A file list naming a path outside the repository (an absolute path, a `..`, `.` or `.git` component, or a path through a symlinked directory, which only a hand-built index can hold) refuses the scan or audit (exit 2, nothing recorded; see [Files the repository names](trust-model.md#files-the-repository-names)).

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

Comparability: a Rust scan compares with the baseline only when hangover's Rust analysis version, every tool version (cargo, clippy, ast-grep, jscpd, cargo-machete), the policy file and the set of available sections are unchanged; otherwise `verify` blocks with `run hangover scan --rebaseline`. Installing cargo-machete mid-campaign is such a change, and so is moving between static and executing scans (static scans lack the clippy and machete sections). A compile error, or any error-level diagnostic in a library target (cargo then never checks the crates that depend on it), makes the clippy section `partial`: verify cannot pass on that scan and no clippy card goes stale. An error-level lint in a test, binary or example target (clippy's `never_loop`, say) blocks nothing downstream; it is listed as a warning for the gate to deal with, not as a hangover finding.

`audit --base REF` writes the base commit's files from git objects into hangover's own directory, `.hangover/rust-audit/tree`, analyzes them, and fails on any card the working tree has that the base does not. Nothing is checked out (`git ls-tree` and `git cat-file --batch` only), so no hook or filter runs, and git is never run inside the tree. The tree is kept between audits and synced in place, so a file the base did not change keeps its mtime and cargo stays incremental; it shares this tree's hangover target directory. The first audit of a large workspace compiles its crates once more under that path. hangover refuses, and never reuses or removes, a `.hangover/rust-audit/tree` it did not create (a symlink, a directory without its owner marker, or files the repository tracks there).

Building the base tree runs its build scripts (audit always executes; see [Trust model](trust-model.md)). They run with git discovery stopped at the tree (`GIT_CEILING_DIRECTORIES`), so a build script that calls `git rev-parse` or `git describe` finds no repository and takes its no-git fallback, as for a crate downloaded from a registry, instead of reading the checkout's HEAD. A build script that opens `../.git` by path still reaches the checkout; nothing short of a separate clone prevents that.

On a case-insensitive or Unicode-normalizing volume (the macOS default), two names in the base commit that differ only by case or normalization are one directory entry. The audit then fails, naming both, rather than analyzing a tree that is not the commit: audit from a clone on a case-sensitive volume.

A mixed repository (a TypeScript gate driving cargo, say) can turn Fallow off for a Rust-only campaign with `"fallow": {"enabled": false}` in `.hangover/config.json`, and `"rust": {"enabled": false}` does the reverse.

Known limits: the `pub` analysis is textual, so a name built by a macro or generated by a build script can look unused (the compiler then rejects the deletion, so the gate is the backstop); cargo-machete reads source text and misses dependencies used only through features or macros; `#[cfg]`-gated code outside the built feature set is invisible to rustc's dead-code lint; only the analyzed root's `clippy.toml` is merged into hangover's clippy configuration. Static mode has no compiler evidence at all (no `complexity`, `dead_code`, `unused_imports` or `unused_dependencies` cards), and its workspace reader follows cargo's rules for members, excludes, path dependencies and inherited fields but never looks above the repository root. Static mode needs git 2.42 or newer; executing Rust scans accept older git.
