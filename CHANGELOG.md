# Changelog

## 0.1.0 (unreleased)

The first public version. The README describes the whole tool; this entry records what changed late in the 0.1.0 line, because some of it changes behaviour for anyone running an earlier development build.

### Breaking rename: deslop → agent-hangover

- The npm package is now `agent-hangover` (formerly `deslop-tooling`). Install it from
  `https://github.com/treygoff24/agent-hangover`; analyzer versions are unchanged.
- Replace the `deslop` command with `hangover`. The equivalent `agent-hangover`
  command is a fallback when another tool owns the short name; both launch the
  same isolated Python process. No old command alias is installed.
- Python imports and module execution move from `deslop` to `hangover`
  (`python3 -m hangover`); the source and launcher are now `src/hangover` and
  `bin/hangover`. CLI help, version output and doctor tool keys use `hangover`.
- Rename every `DESLOP_*` environment variable to `HANGOVER_*` (including analyzer
  and reviewer binary overrides). The old variables have no fallback.
- Campaign state moves from `.deslop/` to `.hangover/`, including config, runs,
  owner marker and `.hangover/rust-audit/tree`. No command reads legacy state in
  place. The tracked-state refusal now applies only to `.hangover/`.
- Rename committed Rust policy `.deslop-rust.json` to `.hangover-rust.json`.
- The agent skill moves from `skills/deslop` to `skills/hangover`, is named
  `hangover`, and is invoked as `$hangover` by agents that use that syntax.
- New local excludes are only `/.hangover/` and `/.fallow/`. Unused predecessor
  discovery and exclusions have been removed. The first static scan no longer
  warns you to select the static mode you are already using.

#### Migrating a development install or campaign

1. Back up campaign state before making changes. Remove the old npm install
   (`npm uninstall -g deslop-tooling`) or old launcher link, install
   `agent-hangover`, and update scripts, Python imports, environment variables,
   and agent skill links to the names above. The npm package named `hangover`
   is unrelated; do not install it for this tool.
2. Before running `hangover init`, move your own existing campaign with
   `mv .deslop .hangover` while `.hangover` does not exist, and rename
   `.deslop-rust.json` to `.hangover-rust.json` if present. A same-filesystem move
   preserves the directory's parent/device/inode owner binding. The marker
   accepts exactly the old or new tool label; newly written markers use
   `hangover`. A copied or cross-filesystem campaign needs `hangover init` to
   adopt it before static mode can use it (only do this for state you trust).
3. Update embedded old paths in your own `.hangover/config.json` and saved
   campaign artifact references (for example remediation `fix_dir` paths),
   command wrappers, and any custom analysis ignore rules. No automated rewrite
   is performed. Leave old immutable run evidence intact, finish or re-run
   pending verifications, and run `hangover scan --rebaseline` in a trusted
   checkout before continuing. Old review packets and proofs are not fresh
   verification under the new tool version.
4. `hangover init` writes the new local excludes; remove a stale `/.deslop/`
   exclude yourself if desired. Re-link the skill from the new package's
   `skills/hangover` directory, then run `hangover doctor`.

When only `.deslop/` exists, doctor and initialization print one informational
migration line; `doctor --json` keeps that line on stderr. Initialization
(including implicit initialization on scan/run) stops with exit **1** (`blocked`,
a user action is required, not a security refusal) and creates no `.hangover/`.
Move your own campaign as above, or explicitly run `hangover init --ignore-legacy`
to start a fresh campaign without reading or changing legacy state. `--force`
does not bypass this decision. Old state remains foreign data until you move it
yourself; no command performs an automatic migration.

### Install

- hangover installs with npm as the package `agent-hangover`, which provides a `hangover` command. Fallow 3.31.0, `@ast-grep/cli` 0.50.0 and jscpd 5.4.1 are exact-pinned runtime dependencies, and a `files` allowlist keeps tests and development material out of the package. The package is not published to the npm registry: install it from the Git repository or from a tarball made with `npm pack`. A clone with `npm ci` remains the development route.
- The launcher re-runs the first `python3` on `PATH` (3.11 or newer) in isolated mode (`python3 -I`), so `PYTHONPATH`, the user site directory and the current directory cannot shadow the standard library or hangover.

### Security hardening

These changes are breaking: a repository or campaign that worked before may now be refused.

- **One containment rule, every mode.** A file the repository names (`package.json` and workspace manifests, the gate script a package script runs, the `Makefile`, Cargo manifests, Rust sources, `.hangover-rust.json`, `clippy.toml`, `.fallowrc.json`, lockfiles and other verification inputs, cited and untracked files) is refused when its path is absolute, has a `..` component, has a symlink in any component, is a hard link, or resolves outside the repository. A refused file is never opened, hashed or printed, and the command exits 2. This applies to trusted repositories too: a gate such as `bash ../shared/gate.sh` or a symlinked `package.json` is now refused.
- **One validated file list.** Inventory, issue selection, review scope and the Rust analysis all read the git file list through the same check. An entry that is absolute, has a `..`, `.` or `.git` component, or leads through a symlinked directory now refuses the scan (exit 2), where the Rust analysis used to record a `failed` section.
- **Refused scans are not recorded.** A refused scan merges nothing and is never the baseline or the latest run; `status` exits 2 while it stands, until a scan completes. Every security refusal is a `tool_error`, exit 2.
- **Shipped state is refused.** A `.hangover/` the repository tracks is refused by every command except `hangover fallow`. In static mode an existing `.hangover/` must also carry hangover's owner marker (`.hangover/owner`). A campaign created by an earlier build needs `hangover init` once before `--no-checks` will use it.
- **Static mode (`--no-checks`) reads only a regular clone.** A gitfile (linked worktree, submodule directory), a `.git` with `commondir`, `objects/info/alternates` or a symlink inside it (outside `hooks/`), and a `core.worktree` pointing elsewhere are refused. A bare repository is never discovered (`safe.bareRepository=explicit`).
- **Static mode reads the git config without includes.** A config using `include.path` or `includeIf.*.path` is refused. Every static-mode git command has a 120-second deadline, after which the run is refused.
- **Static mode no longer runs Fallow.** The Fallow section is `skipped` (not a failure). Fallow follows `tsconfig` chains, `node_modules` manifests and plugin files that a checkout can point outside itself. `scan --rebaseline --no-checks` is blocked; once the checkout is trusted, `hangover scan --rebaseline` records Fallow.
- Static mode leaves hard-linked files out of the file list. `hangover init` writes `.git/info/exclude` only into the checkout's own `.git`. The environments hangover gives git and its analyzers drop relative `PATH` entries.
