# Trust model

hangover is a quality harness, not a sandbox. It runs as you, with your permissions, files and credentials. Whether it runs a repository's own code depends on the mode you choose, and that choice is yours to make per checkout.

| | Executing mode (the default) | Static mode (`--no-checks`) |
|---|---|---|
| For | a checkout you would build and test yourself | a checkout you do not trust yet |
| Runs the repository's checks | yes | no |
| Runs cargo (build scripts, proc macros) | yes, for a Cargo workspace | no |
| Runs Fallow | yes | no (section `skipped`) |
| Where it runs | any checkout you trust | a regular clone only (no linked worktree, no submodule) |
| Sends source to a model | yes, unless `--no-review` or `--runner none` | yes, unless `--no-review` or `--runner none` |

The rule for [files the repository names](#files-the-repository-names) and the rules for [state the checkout ships](#state-the-checkout-ships) hold in both modes.

## Executing mode

Executing mode is `run` and `scan` without `--no-checks`, every `verify` and `audit`, `suppress` (its rebaseline scan), and any command that invokes a `command` reviewer. These can run repository-controlled code:

- the configured native checks (`run`, `scan --checks`, `verify`, `audit`), with your normal environment;
- for a Cargo workspace, `cargo metadata`, `cargo clippy` and `cargo machete` (every analyzer scan outside static mode, plain `scan` without `--checks` included). Clippy compiles the workspace, so the repository's build scripts and proc macros run, and rustup obeys its `rust-toolchain.toml`. `audit` builds the base commit too;
- a `command` review runner from `.hangover/config.json`, which is an unsandboxed subprocess.

Use executing mode only on a checkout you would be willing to build and test yourself.

## Static mode

Static mode (`hangover run --no-checks`, `hangover scan --no-checks`) is for reading a checkout you do not trust. Run it on a fresh `git clone`:

```bash
git clone https://example.com/someone/project.git && cd project
hangover run --no-checks --no-review
cat .hangover/config.json        # the checks hangover found; nothing has run them
```

Static mode guarantees, as far as the code below goes:

- no configured check runs, and cargo, rustup, clippy and cargo-machete are never started. Rust analysis reads the `Cargo.toml` files as data and the sources with the bundled ast-grep and jscpd; clippy and cargo-machete sections are `skipped`, so the Rust result is `partial`;
- Fallow does not run. Its section is `skipped`, which is not a failure (`scan` and `run` still exit 0): Fallow follows `tsconfig` `extends` chains, `node_modules` manifests and plugin files, which a checkout can point outside itself, and no precheck can bound that. TypeScript and JavaScript sources therefore get no deterministic analysis in static mode, and existing Fallow cards are left as they were;
- only a regular clone is read. The directory holding `.git` must have a real `.git` directory with no `commondir` file, no `objects/info/alternates` and no symlink inside it (its `hooks/` directory aside). A gitfile (a linked worktree, a submodule's own directory, or any other pointer to a git directory elsewhere) is refused, and so is a config whose `core.worktree` moves the work tree. Scan a fresh `git clone` of the checkout instead. git is told never to discover a bare repository (`safe.bareRepository=explicit`), so a directory that is itself a bare repository is read as a plain tree, not through git;
- before any git runs in the checkout, hangover reads `.git/config` (and `.git/config.worktree`) itself, with includes off, and refuses a config that uses `include.path` or `includeIf.*.path`: git would read the included file, wherever it is, for every command;
- every git command run in static mode reads no system or global git config, takes attributes from the empty tree (so `.gitattributes` selects no filter or diff driver), turns `core.fsmonitor`, `core.hooksPath`, the pager, editor, ssh, askpass and credential helper off, and overrides with an empty value every command-valued key the repository's config defines (filter, textconv, diff and merge drivers, pagers, gpg programs, remote commands, config-defined hooks). No transport is allowed, whatever `protocol.*.allow` the repository sets, and no missing object is fetched from a promisor remote (an `ext::` remote URL is a command). The exclude, attributes, diff order and mailmap files a config could name are all `/dev/null`, so git opens no file outside the checkout because the config says to. `git status` does not descend into submodules. This needs git 2.42 or newer; on older git, static mode refuses to start;
- every git command has a deadline of 120 seconds (`STATIC_GIT_TIMEOUT_SECONDS` in `src/hangover/repository.py`). A FIFO or device where git expects a file would otherwise stall it; past the deadline the run is refused;
- ast-grep and jscpd get hangover's own configuration, so the repository's `sgconfig.yml`, `.jscpd.json` or `jscpd` key in `package.json` is never read;
- a file the checkout holds as a hard link (more than one name for one file, which a git checkout never makes) is left out of the file list, with a note;
- an existing `.hangover/` is used only if hangover's owner marker binds it to this directory (see [State the checkout ships](#state-the-checkout-ships)).

Every refusal above exits 2 and names its reason. For example, on a linked worktree:

```text
hangover: refusing /work/wt1 under --no-checks: /work/wt1/.git is a gitfile (a linked worktree, a submodule, or a pointer to another git directory), not a directory; static mode reads only a regular clone, ...
```

What static mode does not do:

- it is not a sandbox. git and the bundled analyzers are third-party binaries reading untrusted input, with your permissions;
- a review, unless you pass `--no-review`, sends the source to the configured model provider, and a `command` runner executes;
- a static scan cannot become a rebaselined baseline: `scan --rebaseline --no-checks` is blocked (exit 2) whenever it skipped Fallow or ran the Rust analysis without cargo. The very first scan of a campaign is recorded as its baseline whatever the mode; after a static first scan, run `hangover scan --rebaseline` once the checkout is trusted, which records Fallow and the full Rust analysis.

`init` in static mode still discovers the checks and writes them to `.hangover/config.json`, without running them, so you can read what executing mode would run before you allow it.

## Files the repository names

This rule holds in every mode. hangover reads some files because the repository points at them or by convention: `package.json` and workspace manifests, the gate script a `package.json` script runs, the `Makefile`, the Cargo manifests (root, ancestors and members), Rust sources, `.hangover-rust.json`, the analyzed root's `clippy.toml`, `.fallowrc.json` (for `suppress`), lockfiles and other verification inputs, the files a finding cites, and untracked files shown in review patches. Such a path is refused if it is absolute, has a `..` component, has a symlink in any component (the file itself included), is a hard link, or resolves outside the repository. A refused file is never opened, hashed or printed, and the command exits 2.

The file list git reports gets the same rule: an entry that is absolute, has an empty, `.`, `..` or `.git` component, leads through a symlinked directory or resolves outside the repository refuses the whole scan (only a hand-built index can hold one). A tracked symlink itself is skipped, not refused: hangover reads no symlink. Lookups that only ask whether a file exists (`tsconfig.json`, the lockfile that picks the package manager, `node_modules`) treat a symlink as absent.

This applies to repositories you trust, too, and that is deliberate: no mode reads, stores or prints a file outside the checkout because the checkout pointed at it. A gate such as `"verify": "bash ../shared/gate.sh"`, or a `package.json` that is a symlink into a shared directory, is refused: `init` (and so `run` on a new campaign) and `doctor` exit 2 on such a gate, and every scan exits 2 on such a `package.json`:

```text
hangover: refusing symlinked or external gate script '../shared/gate.sh' (named in package.json): '../shared/gate.sh' has a '..' component
```

Move the script into the repository as a regular file. The environments hangover gives git and its analyzers also drop relative `PATH` entries, so the checkout cannot supply the `node` or `git` they run (native checks keep your normal environment).

A refused scan merges nothing and is never saved as the baseline or the latest run; `status` exits 2 and names the refusal until a scan completes.

## State the checkout ships

Everything hangover reads from `.hangover/` (the checks and review command in `config.json`, `state.json`, run snapshots, gate proofs) is trusted as its own, so two rules keep a checkout from supplying it:

- in every mode, a `.hangover/` path the repository tracks (in any letter case) is refused by every command except `hangover fallow`. hangover never commits `.hangover/`, so tracked state came with the checkout. Remove it from the index (`git rm -r --cached .hangover`) and delete the directory if you did not create it;
- in static mode, an existing `.hangover/` must carry hangover's owner marker (`.hangover/owner`), which records the repository path and the device and inode of `.hangover/` itself, so an archive cannot forge it. `hangover init` writes the marker when it creates the directory and adopts an existing one when you run it. A campaign that was moved or copied to a new path needs `hangover init` once before `--no-checks` will use it.

Executing commands still accept an unmarked, untracked `.hangover/`, so if the checkout came with one, read `.hangover/config.json` or delete the directory before running anything beyond static mode.

## Review runners

The `codex` and `delegate` review runners ask those tools for their read-only modes; that guarantee belongs to the invoked tool and holds exactly as far as that tool enforces it. The `command` runner is a trusted unsandboxed subprocess, in the same trust class as native checks. See [Fresh-context review](review.md).

## Safety rules for remediation

These are the rules hangover's packets and reviewer hold a fix to, and the rules its own code follows:

- Preserve behavior over cleanliness.
- Investigate public APIs, routes, reflection, dependency injection, plugins, generated files, schemas, migrations, environment variables, serialization, CI, and deployment before deletion.
- Never weaken types, lint, tests, security, or analyzer configuration to produce a better result.
- Never auto-suppress findings.
- Keep remediation batches coherent and small; avoid broad formatting churn.
- Compare Fallow metrics only under the same version and resolved configuration.
- Treat an analyzer score as directional evidence, not a target.
- Reopen a supposedly resolved deterministic finding when a later scan sees it again.
- Refuse symlinked state paths, and any repository-named file or listed path that is absolute, has `..`, passes through a symlink, is a hard link or resolves outside the repository, rather than reading or writing outside the target repository.
- Disable repository fsmonitor and external-diff execution for harness-controlled git reads, and in static mode every repository-configured git driver; omit analyzer state and secret-looking untracked files from review patches.

## Reporting a vulnerability

hangover's job includes reading checkouts you may not trust, so a way for a repository to make hangover read outside itself, run its code in static mode, or choose hangover's checks or reviewer is a security bug. Report one privately through GitHub's security advisories on this repository (the "Report a vulnerability" button under its Security tab) rather than in a public issue. Include the hangover version (`hangover --version`), the command, and a minimal checkout that reproduces it.
