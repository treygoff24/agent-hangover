# Fresh-context review

Every item hangover closes needs a pass from a reviewer that did not write the fix: a separate model run with a fresh context that sees the diff, the evidence and the invariants, and never the backlog or earlier verdicts. This page covers the reviewer contract, the four ways to run one (`codex`, `delegate`, `command`, `none`), the review settings in `.hangover/config.json`, and what to do when a runner fails.

| Runner | What runs the review | Set up |
|---|---|---|
| `codex` (default) | [Codex CLI](https://github.com/openai/codex) in its read-only sandbox | install Codex and run `codex login` |
| `delegate` | the [delegate](https://github.com/treygoff24/delegate-agent) CLI, routing to a lane such as `codex` or `claude` | install delegate and authenticate the lane's CLI |
| `command` | your own executable, given an argv template | see [Command review runners](command-review-runner.md) |
| `none` | nothing: hangover prepares the packet and you run a reviewer yourself | none |

Choose per command with `--runner`, or set the default in `review.runner`.

## Reviewer contract

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

## Codex runner

`codex` is the recommended default. Its invocation, abbreviated:

```bash
codex exec --ephemeral --ignore-user-config -c project_doc_max_bytes=0 \
  -c shell_environment_policy.inherit=none ... -s read-only --add-dir TARGET \
  --output-schema schemas/review.schema.json -o RUN/review.json -C TEMPDIR --skip-git-repo-check -
```

It runs from a temporary directory outside the target, with project instruction files disabled and user config ignored; the shell commands Codex runs get a run-local `HOME` and none of the inherited environment. The prompt arrives on stdin.

## Delegate runner

`delegate` is a separate command-line tool, [delegate-agent](https://github.com/treygoff24/delegate-agent) (`pipx install delegate-agent-cli`, or `uv tool install delegate-agent-cli`), that runs one prompt through a chosen coding-agent CLI (Codex, Claude Code and others), called a lane; hangover only shells out to it and never bundles it. Set `review.runner` to `delegate` to route reviews through it. If you use delegate, any model it exposes can review. Configure its lane (default `codex`), optional model, and optional reasoning effort in `.hangover/config.json`; `--lane`, `--model`, and `--reasoning-effort` override those values on `hangover review` and `hangover verify`.

For lanes without harness-level schema enforcement, hangover embeds the schema in the prompt and validates the returned JSON. Set `HANGOVER_DELEGATE_BIN` to an exact delegate binary path, just as `HANGOVER_CODEX_BIN` overrides Codex.

Because a lane need not share a filesystem with hangover, the delegate prompt inlines the review packet and any before/after patches instead of pointing at them. File paths recorded inside the packet, such as raw Fallow artifacts, are therefore not readable from the reviewer's context; only the inlined content is available to it.

## Command runner

Set `review.runner` to `command` and `review.command` to an argv array for a bring-your-own reviewer. The command runs with the target repository as its working directory; hangover captures stdout/stderr and validates the resulting JSON. Placeholders replace a whole argument only, never a substring:

| Placeholder | Substituted value |
|---|---|
| `{prompt}` | Generated review prompt path. |
| `{output}` | Review JSON output path. |
| `{repo}` | Target repository path. |
| `{schema}` | Review schema path. |

If the template contains `{prompt}`, hangover passes the generated prompt file path and does not send the prompt on stdin. If it omits `{prompt}`, hangover sends the prompt on stdin instead. If the template omits `{output}`, hangover parses stdout as the review JSON. A command that exits successfully but emits invalid JSON is still an invalid review.

The full contract for a wrapper, with a worked example, is in [Command review runners](command-review-runner.md).

## Review configuration

The generated config includes every runner key:

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

The issue stays in progress until review passes. `verify --no-review` records deterministic evidence without preparing a review; `review --issue ISSUE --prepare` can then prepare one from that evidence. 

## What a verification binds

Each verification has its own before/after patches, snapshot, native-check logs, and analyzer artifacts. Closure checks their hashes and the remediation attempt, member set, notes, waivers, baseline, check policy, analyzer config, and verifier inputs. Tracked and non-ignored untracked working-tree content must still match after checks and after review. A new verification invalidates the previous proof before running any checks, even if the new run fails. A passing import consumes its token in the same state update that resolves the batch; an unrelated scan does not replace that import's evidence.

Updating hangover's verifier code, schema, or post-fix prompt invalidates pending proofs in existing campaigns; run verification again with the updated tool.

Implementer notes receive stable IDs. A passing review must assess each issued note once, reference its ID in `note_id`, and cite evidence. Missing, duplicate, unrelated, or rejected assessments cannot close a remediation.

Staging or committing unchanged working-tree content does not invalidate the proof. HEAD is recorded as provenance, not as content identity. This is not a staged-commit or Git-history proof. Ignored dependencies, external services, arbitrary command environments, and transitive tool installations are not frozen. Hash checks detect drift at execution boundaries; they do not defend against a hostile concurrent writer changing inputs and changing them back. A protected merge policy must own any stronger enforcement boundary.
