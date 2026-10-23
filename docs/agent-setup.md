# Setting up agent-hangover for a user

You are an AI coding agent (Claude Code, Codex, pi or another) and your user asked you to install or set up agent-hangover. Work through the steps in order; each ends on a check you can run. Ask your user the questions in step 4 before you run hangover on their code.

agent-hangover is a command-line tool, `hangover`, that runs behavior-preserving cleanup campaigns on a repository: it discovers the repository's own checks, runs pinned static analyzers (Fallow for TypeScript/JavaScript, an experimental set for Rust), asks a separate fresh-context model to review each fix, and keeps a backlog in `.hangover/` inside the repository. It never edits product code itself. The [README](../README.md) is the user-facing overview; [trust-model.md](trust-model.md) is the security boundary.

## 1. Check the prerequisites

Run each check and compare against the requirement:

```bash
uname -s                 # Darwin or Linux. Windows is not supported (WSL is untested).
python3 --version        # 3.11 or newer, and it must be the first python3 on PATH
node --version           # v22 or newer
npm --version            # any; npm 12 needs the flags in step 2
git --version            # any for normal use; 2.42 or newer for static mode (--no-checks)
```

Optional, depending on the step 4 answers:

```bash
codex --version          # the default reviewer (Codex CLI)
delegate --version       # the delegate reviewer (https://github.com/treygoff24/delegate-agent)
cargo clippy --version   # needed for Rust repositories
cargo machete --version  # optional Rust unused-dependency findings
```

When a required tool is missing or too old, tell your user which one and stop; installing a language runtime is their decision.

Done when: the OS is macOS or Linux, and `python3`, `node` and `git` meet the versions above.

## 2. Install

hangover is not published to the npm registry. Install it from GitHub:

```bash
npm install -g --allow-git=root --allow-scripts=@ast-grep/cli \
  git+https://github.com/treygoff24/agent-hangover.git
```

`--allow-git=root` lets npm 12 install from a Git URL (npm 12 refuses by default with `EALLOWGIT`). `--allow-scripts=@ast-grep/cli` lets the bundled ast-grep copy its native binary into place. npm 10 and 11 accept both flags. Leave out `--ignore-scripts`.

When the install fails with `EACCES`, npm's global prefix is a system directory. Tell your user and offer the two usual fixes (a user-owned prefix via `npm config set prefix ~/.npm-global`, or a Node version manager); run `sudo` only if they ask you to.

The npm package is `agent-hangover`; it installs two identical commands, `hangover` and `agent-hangover`. An unrelated registry package is named `hangover`; never `npm install -g hangover`.

Done when: `npm install` exits 0.

## 3. Verify the install

```bash
command -v hangover || echo "not on PATH: add $(npm prefix -g)/bin to PATH"
hangover --version
"$(npm root -g)/agent-hangover/node_modules/.bin/ast-grep" --version
hangover doctor; echo "doctor exit: $?"
```

Expected:

- `hangover --version` prints `hangover 0.1.0` (or newer).
- The ast-grep line prints `ast-grep 0.50.0` with no `[warn] postinstall script did not run` line. If the warning appears, reinstall with `--allow-scripts=@ast-grep/cli`. Without it ast-grep still works, but slowly.
- `hangover doctor` prints a `fallow: fallow 3.31.0 (pinned 3.31.0)` line. It exits 0 when the configured reviewer can start, and exits 1 with `missing: codex (not logged in)` (or `codex` not found) when it cannot. Exit 1 for the reviewer alone is expected until step 4 is settled. Any other `missing:` entry is an install problem.

If `hangover` names a different tool on this machine, use `agent-hangover` everywhere instead.

Then prove the whole pipeline on a throwaway repository, without touching your user's code:

```bash
demo="$(mktemp -d)/hangover-smoke"
mkdir -p "$demo/src" && cd "$demo" && git init -q
cat > package.json <<'EOF'
{ "name": "hangover-smoke", "version": "1.0.0", "private": true, "type": "module",
  "scripts": { "test": "node test.js" } }
EOF
cat > src/format.js <<'EOF'
export function formatName(user) { return user.first + " " + user.last; }
export function formatNameOld(user) { return user.first + " " + user.last; }
EOF
cat > test.js <<'EOF'
import assert from "node:assert";
import { formatName } from "./src/format.js";
assert.equal(formatName({ first: "Ada", last: "Lovelace" }), "Ada Lovelace");
EOF
git add -A && git -c user.name=smoke -c user.email=smoke@example.invalid commit -qm "smoke test"
hangover run --no-review
hangover next
echo "smoke repository: $demo"
```

Expected: `test: passed (baseline)`, a `fallow: completed` line, `issues: obsolete=0, open=1, stale=0`, and a next item `Unused export: formatNameOld in src/format.js`. Afterwards, delete the printed smoke repository with `rm -rf` on that path.

Done when: `hangover --version` works, `hangover doctor` reports Fallow 3.31.0 and no missing tool other than the reviewer, and the smoke repository produces the `formatNameOld` card.

## 4. Ask your user

These decisions belong to your user. Ask them together, in one message, and use the safe default for anything they leave unanswered.

| Decision | Options | Safe default |
|---|---|---|
| Is the target repository trusted to run on this machine? Executing mode runs its checks (tests, build) and, for Rust, cargo with its build scripts and proc macros, all with the user's permissions. | trusted: executing mode; untrusted: static mode, `--no-checks`, on a fresh `git clone` | untrusted |
| May source code be sent to a model provider for review? | yes, with the reviewer below; no: `--no-review`, or `--runner none` to prepare review prompts the user runs elsewhere | no |
| Which reviewer runs the fresh review? | `codex` (Codex CLI; the user runs `codex login`); `delegate` (the delegate CLI, plus a lane such as `codex` or `claude`); `command` (the user's own executable, which runs unsandboxed; see [command-review-runner.md](command-review-runner.md)); `none` (prepare prompts only) | `none` |
| Which skill directories should get the hangover skill? | the harness you run in; others the user names | only the harness you run in |
| For a Rust repository, install cargo-machete for unused-dependency findings? (`cargo install cargo-machete` compiles and installs software.) | yes / no | no |

Some decisions come up later, during a campaign; ask when they do:

- the gate: if `hangover init` found no checks, or the wrong ones, ask the user which commands define "still works" and edit `.hangover/config.json` to match. Verification with no configured checks needs `--model-only`, which leaves only the model review as evidence; use it only with the user's explicit agreement;
- switching a repository from static to executing mode (`hangover scan --rebaseline` after a static first scan) needs the user to say the checkout is now trusted;
- `hangover suppress` edits tracked files (`.fallowrc.json` or `.hangover-rust.json`) and makes a finding repository policy; propose it, and run it when the user agrees;
- a `.hangover/` directory that was already in the repository when you arrived came with the checkout or from another person's campaign. Ask before running `hangover init` on it, since `init` adopts it.

Decisions you can take yourself: using `agent-hangover` when `hangover` is taken, running `hangover doctor` and the read-only commands (`status`, `next`, `list`, `preview`), passing `--json` to commands you parse, and starting an untrusted repository in static mode.

Done when: you have an answer or the safe default for each row of the table.

## 5. Install the agent skill

The skill at `skills/hangover/SKILL.md` teaches an agent the campaign loop. Link it into the skill directories your user chose:

```bash
SKILL="$(npm root -g)/agent-hangover/skills/hangover"
test -f "$SKILL/SKILL.md" && echo "skill found"
mkdir -p ~/.claude/skills && ln -s "$SKILL" ~/.claude/skills/hangover    # Claude Code
mkdir -p ~/.agents/skills && ln -s "$SKILL" ~/.agents/skills/hangover    # Codex, pi, other Agent Skills readers
```

`~/.agents/skills` is where Codex and pi read user skills. Another harness takes the same directory in its own skills location. `ln -s` fails if the name already exists; when it does and the existing entry is not a link to this package, ask before replacing it.

The skill is invoked as `$hangover` in Codex and `/hangover` in Claude Code. A harness loads new skills when a session starts, so tell your user that a new session picks it up.

Done when: `ls -l ~/.claude/skills/hangover` (or the chosen directory) shows a link to `.../agent-hangover/skills/hangover`, and `SKILL.md` is readable through it.

## 6. Configure the reviewer

The reviewer is set per repository in `.hangover/config.json`, which `hangover init` (or the first `hangover run`) creates. `hangover init` reads the repository's files and runs git, but none of the repository's checks. In an untrusted repository, let the static run in step 7 create the config, then set the runner in that clone.

For `codex`: your user runs `codex login` themselves (it is an interactive sign-in). Then `hangover doctor` in the repository should exit 0.

For `delegate`: install it (`pipx install delegate-agent-cli` or `uv tool install delegate-agent-cli`), have your user authenticate the CLI behind the chosen lane, then set the runner and lane from the repository root. In a trusted repository, run `hangover init` first; in an untrusted one, the static run in step 7 has already created the config.

```bash
python3 - <<'EOF'
import json, pathlib
path = pathlib.Path(".hangover/config.json")
config = json.loads(path.read_text())
config["review"]["runner"] = "delegate"          # or "none", "codex", "command"
config["review"]["delegate"]["lane"] = "claude"  # delegate only
path.write_text(json.dumps(config, indent=2) + "\n")
EOF
hangover doctor
```

For `command`: follow [command-review-runner.md](command-review-runner.md); `review.command` is an argv array, and the command runs as the user with no sandbox.

For `none` or no review: nothing to configure. Pass `--runner none` (prepare review prompts) on `run`, `review` and `verify`, or `--no-review` (skip review) on `run` and `verify`; or set `review.runner` to `"none"` with the snippet above.

Done when: `hangover doctor` in the repository exits 0, or the user chose `none` or no review.

## 7. First real run

Untrusted repository (the default): clone it fresh and scan statically. Static mode refuses a linked worktree, a submodule and a git config with `include.path`/`includeIf` (exit 2), so always scan a fresh clone:

```bash
scan_dir="$(mktemp -d)/repo"
git clone <the repository URL or path> "$scan_dir" && cd "$scan_dir"
hangover run --no-checks --no-review
cat .hangover/config.json
hangover status
```

Static mode runs no check, no cargo and no Fallow, so a TypeScript/JavaScript repository gets no analyzer findings here; the point is to show your user the checks hangover would run (`checks` in `config.json`) before they decide to trust it.

Trusted repository: from the repository root,

```bash
hangover run --no-review          # or with the runner chosen in step 4: hangover run --runner codex
hangover next --json
```

Report to your user: the checks hangover discovered, whether the baseline gate passed (`baseline stages:` in `hangover status`), the issue counts, and the first item from `hangover next`. Then offer to start a batch through the skill; leave the fixing until they ask.

Done when: `hangover status` exits 0 and shows a baseline, and your user has the report.

## Uninstall

```bash
npm uninstall -g agent-hangover
for link in ~/.claude/skills/hangover ~/.agents/skills/hangover; do
  case "$(readlink "$link" 2>/dev/null)" in
    *agent-hangover*) rm "$link" ;;
  esac
done
```

Each repository it ran in keeps a `.hangover/` directory (campaign state and logs), a `.fallow/` cache, and two lines (`/.hangover/`, `/.fallow/`) in `.git/info/exclude`. Ask your user before deleting any of them: `.hangover/` is their campaign record.

## Rules

What hangover never does: edit product code (`fix` prints a packet; the agent edits), run analyzer autofixes, install git hooks, edit CI, install the target repository's dependencies, or commit. It writes `.hangover/`, `.fallow/` and `.git/info/exclude`, and tracked files only through `suppress`.

What you do on your user's behalf only after they say so:

- run executing-mode commands (`hangover run` or `scan` without `--no-checks`, `verify`, `audit`, `suppress`) on a repository they have not called trusted;
- send source to a model provider (any review that is not `--runner none` or `--no-review`);
- sign in to Codex, delegate lanes or any provider; the user does the sign-in;
- use `sudo`, change npm's global prefix, or install other software (Codex, delegate, cargo-machete);
- add hooks or CI steps that call hangover;
- commit `.hangover/` (hangover refuses a repository that tracks it), delete campaign state, or replace an existing skill link.

When hangover refuses something (exit 2: `refusing ...`), report the message to your user and stop. The refusals are the security boundary: a gate script outside the repository (`bash ../shared/gate.sh`), a symlinked `package.json`, a tracked `.hangover/`, a non-regular clone in static mode. The fix is in the repository (move the file inside, clone fresh), never a workaround around hangover.

Read `state` in `--json` output, not only the exit code: exit 0 with `review_pending` means a review is still owed, and only `resolved` means an item closed. Exit codes and the JSON envelope are in [reference.md](reference.md).
