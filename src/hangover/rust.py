"""Deterministic Rust evidence: the Fallow counterpart for Cargo workspaces.

Fallow reads only TS/JS, so a Cargo workspace gets its evidence here, from
existing tools wherever one answers the question:

- `cargo metadata` for the workspace's packages, targets and crate graph;
- `cargo clippy` (JSON messages) for rustc's dead code and unused imports and
  for per-function complexity (`cognitive_complexity`, `too_many_lines`,
  `too_many_arguments`, run at the thresholds in `.hangover-rust.json`);
- `ast-grep` (pinned in package.json) for the item inventory: every function,
  impl, trait, module and type item with its line span;
- `jscpd` (pinned in package.json) for token-level clone detection;
- `cargo-machete` (optional, `cargo install cargo-machete`) for unused
  dependencies.

What no tool answers, hangover computes from that inventory: god files and
oversized modules and crates, `pub` items no other crate names (or that
nothing names at all), and churn hotspots from `git log`. The identifier
index behind the `pub` analysis is textual (comments removed, string contents
kept), so it can miss a use only through generated or macro-built names; the
compiler rejects any wrong narrowing or deletion, so the gate is the backstop.

Findings carry `source: "rust"` and the same card fields as Fallow's. Their
fingerprints are path- and name-based, never line-based, so a card survives
code moving within its file. Repository policy (thresholds, clippy arguments,
exclusions and suppressions) lives in the committed `.hangover-rust.json`.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

from .model import digest, paths, write_json
from .process import run_logged
from . import repository as _repository
from .repository import (IGNORED_DIRS, LISTED_FILES_ARGS, MAX_CAPTURE_BYTES, RepositoryRefusal, captured_text,
                         checked_files, diagnostic_text, git_safe_environment, no_execute_git_active,
                         no_execute_git_env, read_repo_file)

TOOL_ROOT = Path(__file__).resolve().parents[2]
# 2: crate_local_pub is one card per crate (it was one per file).
RUST_ANALYSIS_VERSION = "2"
POLICY_FILE = ".hangover-rust.json"
DEFAULT_CLIPPY_ARGS = ["--workspace", "--all-targets", "--all-features"]
DEFAULT_THRESHOLDS = {
    # Per function (clippy): cognitive complexity, lines of code, parameters.
    "cognitive": 15,
    "function_lines": 100,
    "arguments": 7,
    # Production lines of code (tests excluded) per file, directory module and crate.
    "file_lines": 1000,
    "module_lines": 15000,
    "crate_lines": 40000,
    # Exported `pub` items in one library crate.
    "pub_surface": 200,
    # Clone size (jscpd).
    "clone_tokens": 100,
    "clone_lines": 8,
}
CLIPPY_THRESHOLD_KEYS = {
    "cognitive": "cognitive-complexity-threshold",
    "function_lines": "too-many-lines-threshold",
    "arguments": "too-many-arguments-threshold",
}
COMPLEXITY_LINTS = {
    "clippy::cognitive_complexity": "cognitive",
    "clippy::too_many_lines": "line_count",
    "clippy::too_many_arguments": "arguments",
}
DEAD_CODE_LINTS = {"dead_code": "dead_code", "unused_imports": "unused_imports"}
LINT_FLAGS = ["-W", "dead_code", "-W", "unused_imports",
              *[flag for lint in COMPLEXITY_LINTS for flag in ("-W", lint)]]
# File roles that are test code: integration tests and benches, examples, and the
# files of an out-of-line `#[cfg(test)] mod` (unit_test: inside the crate).
TEST_ROLES = frozenset({"test", "example", "unit_test"})
REQUIRED_SECTIONS = ("metadata", "clippy", "items", "dupes")
# Attributes that export an item to another language or runtime: a `pub` item
# carrying one is used from outside Rust, so the textual index cannot judge it.
EXPORT_ATTRIBUTE = re.compile(
    r"#\[\s*(?:unsafe\s*\(\s*)?(?:no_mangle|export_name|napi|wasm_bindgen|pyfunction|pyclass|pymethods|"
    r"pymodule|uniffi|tauri::command|cxx::bridge|proc_macro|test|bench|tokio::main|tokio::test|ctor)"
)
TEST_ATTRIBUTE = re.compile(r"#\[\s*(?:[\w:]*::)?test\b|#\[\s*bench\b|#\[\s*cfg\s*\(\s*test\s*\)")
CFG_TEST = re.compile(r"#\[\s*cfg\s*\(\s*(?:all\s*\(\s*)?test\b")
VISIBILITY = re.compile(r"^\s*(pub(?:\s*\([^)]*\))?)?\s*")
ITEM_KINDS = {
    "struct": "struct_item", "enum": "enum_item", "trait": "trait_item", "const": "const_item",
    "static": "static_item", "type": "type_item", "union": "union_item",
}
HARM = {
    "complexity": "A function this complex resists safe modification: every branch multiplies the states a maintainer must hold in mind, and defects hide in the interactions.",
    "dead_code": "Code the compiler proves unreachable in this build still costs reading, compiling and maintaining.",
    "unused_imports": "Unused imports mislead readers about a module's dependencies.",
    "unused_pub_items": "A public item nothing names is surface without a user: it costs reading and maintenance and widens the API for no present need.",
    "crate_local_pub": "`pub` items that no other crate uses widen the crate's API: callers elsewhere could start depending on internals, and readers cannot tell the real interface from helpers.",
    "wide_pub_surface": "A crate exporting this many items has no clear interface; every export is a contract other crates can come to depend on.",
    "god_file": "A file this large holds too many responsibilities to understand or change locally; edits collide and reviews cannot hold the whole.",
    "oversized_module": "A module this large is a subsystem without a boundary; its parts can reach each other's internals freely.",
    "oversized_crate": "A crate this large compiles as one unit and offers no enforced boundaries between its parts.",
    "duplication": "Repeated behavior can drift and forces maintainers to hold multiple implementations in mind.",
    "unused_dependencies": "The manifest advertises machinery the crate may not use, costing build time and supply-chain surface.",
}
CHANGE = {
    "complexity": "Extract coherent sub-steps behind existing seams, flatten nesting with early returns and `let ... else`, and split policy from mechanics, without changing any observable behavior.",
    "dead_code": "Delete the unused item, or establish which build configuration needs it and gate it with that `cfg`.",
    "unused_imports": "Remove the unused import.",
    "unused_pub_items": "Trace dynamic and external use (FFI, macros, generated code, other repositories), then delete the item or narrow it.",
    "crate_local_pub": "Narrow these items to `pub(crate)` (or less) together, in one change, unless another crate is meant to use them: one narrowed alone can fail to compile while another `pub` item still exposes it. The compiler rejects any narrowing a user still needs.",
    "wide_pub_surface": "Decide the crate's real interface: narrow helpers to `pub(crate)`, move private machinery behind a module boundary, and re-export only the intended API.",
    "god_file": "Split the file along its responsibilities into sibling modules, moving code without changing behavior; keep the public paths stable with re-exports where callers use them.",
    "oversized_module": "Find the seams inside the module and give them module boundaries (or a crate of their own) with narrow interfaces.",
    "oversized_crate": "Identify independent subsystems and split them into crates with explicit dependencies, or document why the crate must stay whole.",
    "duplication": "First confirm the semantics are genuinely the same, then reuse the smallest existing primitive or consolidate once.",
    "unused_dependencies": "Remove the dependency from the manifest, or record why it is needed (build scripts, macros, feature forwarding).",
}
VERIFY = {
    "complexity": ["Run the narrowest tests covering the function (`cargo test -p <crate>`), then the repository's configured full gate.",
                   "Re-scan and confirm the function's metrics dropped without new findings elsewhere."],
    "default": ["Build every target and feature the gate builds (`cargo clippy --workspace --all-targets --all-features`).",
                "Run the narrow affected tests, then the repository's configured full gate."],
}


# --------------------------------------------------------------------------- policy


def load_policy(repo: Path) -> dict[str, Any]:
    """The committed `.hangover-rust.json` merged over the defaults; strict about its shape."""
    path = repo / POLICY_FILE
    raw: dict[str, Any] = {}
    text = _policy_text(repo)
    if text is not None:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{path} is not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise RuntimeError(f"{path} must contain a JSON object")
    unknown = sorted(set(raw) - {"clippy_args", "thresholds", "exclude", "ignore", "root", "$comment"})
    if unknown:
        raise RuntimeError(f"{POLICY_FILE}: unknown key(s) {', '.join(unknown)}")
    thresholds = dict(DEFAULT_THRESHOLDS)
    given = raw.get("thresholds", {})
    if not isinstance(given, dict):
        raise RuntimeError(f"{POLICY_FILE}: thresholds must be an object")
    for key, value in given.items():
        if key not in DEFAULT_THRESHOLDS:
            raise RuntimeError(f"{POLICY_FILE}: unknown threshold {key!r} (known: {', '.join(DEFAULT_THRESHOLDS)})")
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise RuntimeError(f"{POLICY_FILE}: threshold {key} must be a positive integer")
        thresholds[key] = value

    def strings(key: str, default: list[str]) -> list[str]:
        value = raw.get(key, default)
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise RuntimeError(f"{POLICY_FILE}: {key} must be a list of non-empty strings")
        return list(value)

    root = _validated_root(repo, raw["root"]) if "root" in raw else None
    return {
        "clippy_args": strings("clippy_args", DEFAULT_CLIPPY_ARGS),
        "thresholds": thresholds,
        "exclude": strings("exclude", []),
        "ignore": strings("ignore", []),
        # Only when set, so a policy without it keeps the digest it always had.
        **({"root": root} if root else {}),
    }


def _policy_text(repo: Path) -> str | None:
    """The policy file's text, None when there is none; RepositoryRefusal for a symlinked or external one."""
    try:
        return read_repo_file(repo, POLICY_FILE, purpose=POLICY_FILE)
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{repo / POLICY_FILE} is not UTF-8 text: {exc}") from exc


def _validated_root(repo: Path, value: Any) -> str:
    """`root`: the directory, relative to the repository, whose Cargo.toml hangover analyzes."""
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{POLICY_FILE}: root must be a non-empty relative path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or "\\" in value:
        raise RepositoryRefusal(f"{POLICY_FILE}: root {value!r} must be a path inside the repository, without '..'")
    current = repo
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RepositoryRefusal(f"{POLICY_FILE}: root {value!r} passes through a symlink ({current})")
    return relative.as_posix()


def add_suppression(repo: Path, key: str) -> Path:
    """Add one finding key to the policy's `ignore` list (idempotent)."""
    path = repo / POLICY_FILE
    load_policy(repo)  # Validate before rewriting.
    text = _policy_text(repo)
    raw = json.loads(text) if text is not None else {}
    values = raw.setdefault("ignore", [])
    if key not in values:
        values.append(key)
        write_json(path, raw)
    return path


def _manifest_dir(repo: Path, root: str | None) -> Path | None:
    """The directory whose Cargo.toml hangover analyzes (the repository root unless the policy names
    one), or None when that manifest does not exist."""
    directory = repo / root if root else repo
    return directory if (directory / "Cargo.toml").is_file() else None


def _declared_root(repo: Path) -> str | None:
    try:
        return load_policy(repo).get("root")
    except RuntimeError:
        return None  # An invalid policy is reported by the scan, which loads it strictly.


def applicable(repo: Path) -> bool:
    """Whether the repository gets Rust analysis: its manifest exists, or its policy file exists but is
    invalid (the scan then fails naming the error, rather than the repository passing as not Rust)."""
    try:
        root = load_policy(repo).get("root")
    except RuntimeError:
        return True
    return _manifest_dir(repo, root) is not None


def manifest_notice(repo: Path, listed: list[Path] | None = None) -> str | None:
    """Why a repository that holds Cargo manifests gets no Rust analysis; None when it gets one, or has none.

    `listed` is the tree's file list (default: the repository's, from git)."""
    repo = repo.resolve()
    if applicable(repo):
        return None
    root = _declared_root(repo)
    if root:
        return f"Rust: {POLICY_FILE} sets root {root!r}, which has no Cargo.toml; Rust is not analyzed"
    try:
        listed = _listed_files(repo) if listed is None else listed
    except RuntimeError as exc:
        return f"Rust: could not look for Cargo manifests: {exc}"
    manifests = sorted((path.relative_to(repo) for path in listed if path.name == "Cargo.toml"),
                       key=lambda path: (len(path.parts), path.as_posix()))
    if not manifests:
        return None
    named = ", ".join(path.as_posix() for path in manifests[:5]) + (
        f", +{len(manifests) - 5} more" if len(manifests) > 5 else "")
    return (f"Rust: no root Cargo.toml; found {named}. Rust is not analyzed until {POLICY_FILE} names the "
            f'workspace to analyze, e.g. {{"root": "{manifests[0].parent.as_posix()}"}}')


# --------------------------------------------------------------------------- tools


def cargo_environment() -> dict[str, str]:
    """git_safe_environment plus what a Rust toolchain reads (rustup, mise, cargo, sccache)."""
    environment = git_safe_environment()
    for name, value in os.environ.items():
        if name.startswith(("CARGO", "RUSTUP", "RUSTC", "RUSTFLAGS", "RUSTDOCFLAGS", "SCCACHE", "MISE",
                            "XDG_", "CC", "CXX", "PKG_CONFIG")) and value:
            environment[name] = value
    return environment


def _bundled(name: str, variable: str) -> Path | None:
    override = os.environ.get(variable)
    if override:
        candidate = Path(override).expanduser()
        return candidate if candidate.is_file() else None
    candidate = TOOL_ROOT / "node_modules" / ".bin" / name
    return candidate if candidate.exists() else None


def ast_grep_path() -> Path | None:
    return _bundled("ast-grep", "HANGOVER_AST_GREP_BIN")


def jscpd_path() -> Path | None:
    return _bundled("jscpd", "HANGOVER_JSCPD_BIN")


def _first_line(command: list[str], cwd: Path) -> str | None:
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=60,
                                check=False, env=cargo_environment())
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or result.stderr).strip()
    return output.splitlines()[0] if result.returncode == 0 and output else None


@lru_cache(maxsize=8)
def tool_versions(repo: Path, *, execute: bool = True) -> dict[str, str | None]:
    """Versions as the repository sees them (rust-toolchain.toml applies in its directory).

    execute=False probes no cargo at all: in the repository's directory rustup runs the toolchain
    its rust-toolchain.toml names, which may be any binary on the machine, or downloads one.
    """
    cargo = shutil.which("cargo", path=cargo_environment().get("PATH")) if execute else None
    ast_grep, jscpd = ast_grep_path(), jscpd_path()
    machete = shutil.which("cargo-machete", path=cargo_environment().get("PATH")) if execute else None
    return {
        "cargo": _first_line([cargo, "--version"], repo) if cargo else None,
        "clippy": _first_line([cargo, "clippy", "--version"], repo) if cargo else None,
        "ast_grep": _first_line([str(ast_grep), "--version"], repo) if ast_grep else None,
        "jscpd": _first_line([str(jscpd), "--version"], repo) if jscpd else None,
        "cargo_machete": _first_line([machete, "--version"], repo) if machete else None,
    }


def analyzer_identity(repo: Path) -> dict[str, Any] | None:
    """What verification inputs bind for Rust: the tool versions and the policy file."""
    repo = repo.resolve()
    directory = _manifest_dir(repo, _declared_root(repo))
    if directory is None:
        return None
    # The scan's own rule: a symlinked or external policy is refused here too, never hashed through.
    text = _policy_text(repo)
    return {"analysis": RUST_ANALYSIS_VERSION, "tools": tool_versions(directory),
            "policy": digest(text) if text is not None else None}


def _run(name: str, command: list[str], cwd: Path, out_dir: Path, environment: dict[str, str],
         timeout: int, ok_codes: tuple[int, ...] = (0,)) -> dict[str, Any]:
    stdout, stderr = out_dir / f"{name}.out", out_dir / f"{name}.err"
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        capture = run_logged(command, cwd=cwd, env=environment, stdout_path=stdout, stderr_path=stderr,
                             timeout_seconds=timeout, max_output_bytes=MAX_CAPTURE_BYTES)
    except OSError as exc:
        return {"status": "failed", "exit_code": None, "command": command, "error": str(exc),
                "duration_seconds": round(time.monotonic() - started, 3), "stdout": str(stdout), "stderr": str(stderr)}
    status = capture.status
    if status == "exited":
        status = "completed" if capture.exit_code in ok_codes else "failed"
    result = {"status": status, "exit_code": capture.exit_code, "command": command,
              "duration_seconds": capture.duration_seconds, "stdout": str(stdout), "stderr": str(stderr),
              "stderr_tail": (capture.stderr_tail or "")[-1200:]}
    if status != "completed":
        result["error"] = f"process {status} (exit {capture.exit_code}): " + diagnostic_text(
            capture.stdout_tail, capture.stderr_tail or "")
    return result


# --------------------------------------------------------------------------- git, hermetically

# Git always reads the repository's own config, and whatever it includes, and that config can name
# hooks, filter and diff drivers, a gpg program or an fsmonitor command. So the Rust analysis runs
# only git commands that start none of them (rev-parse, config --list, ls-files, ls-tree, cat-file
# without --filters or --textconv, log --name-only without signatures, external diffs, textconv or
# a pager), and every one of them runs under repository.py's no-execute environment as well
# (`no_execute_git_env`: no system or global config, attributes from the empty tree, hooks and
# fsmonitor off, every command-valued key the repository's config defines overridden as a separate
# GIT_CONFIG_KEY_<n>/GIT_CONFIG_VALUE_<n> pair, so a driver name holding `=` is overridden too; no
# signature is verified, no object is fetched, no mailmap or order file is read). Nothing is ever
# checked out: a checkout runs hooks and filters.


def _no_execute_git(repo: Path) -> tuple[list[str], dict[str, str]]:
    """The argv prefix (`git -C repo`) and environment every Rust-analysis git command runs with.

    Outside `no_execute_git` (an executing scan, which runs the repository's build scripts anyway)
    an older git than the no-execute minimum is accepted; inside it the helper is strict, as the
    CLI's static mode requires. Raises RuntimeError when the environment cannot be built."""
    return ["git", "-C", str(repo)], no_execute_git_env(repo, strict=no_execute_git_active())


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """A git command under the no-execute environment; a failed one (exit 128) when that cannot be built."""
    try:
        prefix, environment = _no_execute_git(repo)
    except RuntimeError as exc:
        return subprocess.CompletedProcess(["git", *args], 128, "", str(exc))
    # Static mode bounds every git: a FIFO where git expects a file would stall it forever.
    timeout = _repository.STATIC_GIT_TIMEOUT_SECONDS if no_execute_git_active() else None
    try:
        return subprocess.run([*prefix, *args], capture_output=True, text=True, encoding="utf-8",
                              errors="surrogateescape", check=False, env=environment, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RepositoryRefusal(f"refusing the checkout under --no-checks: git {args[0] if args else ''} did not "
                                f"finish within {timeout} s; inspect the checkout's .git directory") from exc


def _listed_files(repo: Path) -> list[Path]:
    """repository_files through hermetic git: tracked and untracked, unignored regular files, each one
    inside the repository through real directories (repository.checked_files, the one validator every
    file list goes through). Raises RepositoryRefusal when git lists a name that is absolute, has an
    empty, '.', '..' or '.git' component, leads through a symlinked directory or resolves outside the
    repository: only a hand-built index holds one, and the scan refuses it."""
    inside = _git(repo, "rev-parse", "--is-inside-work-tree")
    listed = _git(repo, *LISTED_FILES_ARGS) if inside.returncode == 0 and inside.stdout.strip() == "true" else None
    return checked_files(repo, listed.stdout if listed is not None and listed.returncode == 0 else None)


# --------------------------------------------------------------------------- workspace


def _workspace(repo: Path, manifest_dir: Path, out_dir: Path,
               environment: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    command = _run("cargo-metadata", ["cargo", "metadata", "--format-version", "1", "--no-deps"],
                   manifest_dir, out_dir, environment, 300)
    if command["status"] != "completed":
        return command, None
    try:
        data = json.loads(captured_text(Path(command["stdout"])))
    except (OSError, ValueError, RuntimeError) as exc:
        command.update(status="invalid_output", error=f"cargo metadata output is not JSON: {exc}")
        return command, None
    root = Path(data.get("workspace_root") or repo).resolve()
    members = set(data.get("workspace_members") or [])
    packages: dict[str, dict[str, Any]] = {}
    for package in data.get("packages") or []:
        if package.get("id") not in members:
            continue
        directory = Path(package["manifest_path"]).resolve().parent
        try:
            relative = directory.relative_to(repo.resolve()).as_posix()
        except ValueError:
            continue
        kinds = {kind for target in package.get("targets") or [] for kind in target.get("kind") or []}
        packages[package["name"]] = {
            "name": package["name"],
            "dir": "" if relative == "." else relative,
            "manifest": (PurePosixPath(relative) / "Cargo.toml").as_posix() if relative != "." else "Cargo.toml",
            "lib": bool(kinds & LIBRARY_ROLES),
            "proc_macro": "proc-macro" in kinds,
            "publishable": package.get("publish") is None or bool(package.get("publish")),
            "path_dependencies": sorted({dependency["name"] for dependency in package.get("dependencies") or []
                                         if dependency.get("path")}),
        }
    refusal = _option_like(packages)
    if refusal:
        command.update(status="failed", error=refusal, refused=True)
        return command, None
    return command, {"root": str(root), "target_directory": data.get("target_directory"),
                     "packages": _link_packages(packages)}


def _option_like(packages: dict[str, dict[str, Any]]) -> str | None:
    """Why a package directory cannot be analyzed: one that starts with '-' would read as a tool's option."""
    named = sorted(package["dir"] for package in packages.values() if package["dir"].startswith("-"))
    return (f"refusing package directory {named[0]!r}: it starts with '-', so a tool given it as a path "
            "could read it as an option") if named else None


def _link_packages(packages: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    for package in packages.values():
        package["dependents"] = sorted(other["name"] for other in packages.values()
                                       if package["name"] in other["path_dependencies"])
        package["path_dependencies"] = [name for name in package["path_dependencies"] if name in packages]
    return packages


DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies", "dev_dependencies", "build_dependencies")
LIBRARY_ROLES = {"lib", "rlib", "dylib", "cdylib", "staticlib"}


def _manifest(repo: Path, path: Path) -> dict[str, Any]:
    """A Cargo.toml inside the repository, parsed. RepositoryRefusal, before it is opened, for one
    outside the repository or reached through a symlink (the manifest or a directory on the way)."""
    if not path.is_relative_to(repo):
        raise RepositoryRefusal(f"refusing symlinked or external Cargo manifest {path}: it is outside the repository")
    relative = path.relative_to(repo).as_posix()
    try:
        text = read_repo_file(repo, relative, purpose=f"Cargo manifest {relative!r}")
        if text is None:
            raise OSError("not a regular file")
        return tomllib.loads(text)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc


def _lexical(base: Path, value: str) -> Path:
    """base/value with '.' and '..' folded as text, the way cargo joins manifest paths; never through a
    link (resolve() would follow one out of the repository and report where it led)."""
    return Path(os.path.normpath(base / value))


def _manifest_path_dependencies(manifest: dict[str, Any], directory: Path, workspace_root: Path,
                                inherited: dict[str, Any]) -> list[tuple[str, Path]]:
    """(package name, directory) of every path dependency, target-specific and workspace-inherited ones too."""
    tables = [manifest, *[table for table in (manifest.get("target") or {}).values() if isinstance(table, dict)]]
    found = []
    for table in tables:
        for kind in DEPENDENCY_TABLES:
            for key, spec in (table.get(kind) or {}).items():
                if not isinstance(spec, dict):
                    continue
                base = directory
                if spec.get("workspace") is True:
                    if not isinstance(inherited.get(key), dict):
                        continue
                    spec, base = inherited[key], workspace_root
                if isinstance(spec.get("path"), str):
                    found.append((str(spec.get("package", key)), _lexical(base, spec["path"])))
    return found


def _workspace_table(manifest: dict[str, Any]) -> dict[str, Any] | None:
    return manifest["workspace"] if isinstance(manifest.get("workspace"), dict) else None


def _explicit_root(manifest: dict[str, Any], directory: Path) -> Path | None:
    """The workspace root a manifest names with `package.workspace = "path"`, if it names one."""
    package = manifest.get("package")
    value = package.get("workspace") if isinstance(package, dict) else None
    return _lexical(directory, value) if isinstance(value, str) else None


def _excluded(root: Path, workspace: dict[str, Any], directory: Path) -> bool:
    """Cargo's `is_excluded`: under an `exclude` entry and not under a literal `members` entry."""
    def under(key: str) -> bool:
        return any(directory.is_relative_to(_lexical(root, item))
                   for item in workspace.get(key) or [] if isinstance(item, str))
    return under("exclude") and not under("members")


def _workspace_root(repo: Path, manifest_dir: Path, top: dict[str, Any]) -> Path:
    """The root of the workspace manifest_dir belongs to, found as cargo finds it: the manifest itself
    when it has `[workspace]`, else the root its `package.workspace` names, else the nearest
    directory above it whose `[workspace]` does not exclude it. The search stops at the repository
    root: hangover never reads above it, where cargo would go on looking."""
    if _workspace_table(top) is not None:
        return manifest_dir
    explicit = _explicit_root(top, manifest_dir)
    if explicit is not None:
        if not explicit.is_relative_to(repo):
            raise RepositoryRefusal(f"{manifest_dir / 'Cargo.toml'} names a workspace root outside the repository ({explicit})")
        if _workspace_table(_manifest(repo, explicit / "Cargo.toml")) is None:
            raise RuntimeError(f"{manifest_dir / 'Cargo.toml'} names {explicit} as its workspace root, which has no [workspace]")
        return explicit
    for ancestor in manifest_dir.parents:
        if not ancestor.is_relative_to(repo):
            break
        if not (ancestor / "Cargo.toml").is_file():
            continue
        manifest = _manifest(repo, ancestor / "Cargo.toml")
        workspace = _workspace_table(manifest)
        if workspace is not None and not _excluded(ancestor, workspace, manifest_dir):
            return ancestor
        named = _explicit_root(manifest, ancestor) if workspace is None else None
        if named is not None and named.is_relative_to(repo):
            return named
    return manifest_dir


def _static_workspace(repo: Path, manifest_dir: Path) -> dict[str, Any]:
    """What `cargo metadata --no-deps` reports, read from the manifests without running cargo.

    The workspace is the one cargo would find for manifest_dir (`_workspace_root`), so a `root`
    naming a member crate analyzes its whole workspace, with its inherited fields. Members are the
    root package, the `workspace.members` globs less `workspace.exclude`, and (as cargo does) every
    path dependency inside the workspace directory. A layout cargo rejects (a member with a
    `[workspace]` of its own, a package its enclosing workspace does not list) raises RuntimeError
    naming cargo's reason, so the static reader never reports a workspace cargo would not.
    """
    repo, manifest_dir = repo.resolve(), manifest_dir.resolve()
    top = _manifest(repo, manifest_dir / "Cargo.toml")
    root = _workspace_root(repo, manifest_dir, top)
    root_manifest = top if root == manifest_dir else _manifest(repo, root / "Cargo.toml")
    workspace = _workspace_table(root_manifest)
    inherited = (workspace or {}).get("dependencies") or {}
    inherited_package = (workspace or {}).get("package") or {}
    manifests: dict[Path, dict[str, Any]] = {}
    if isinstance(root_manifest.get("package"), dict):
        manifests[root] = root_manifest
    if workspace is not None:
        def admit(directory: Path) -> None:
            directory = Path(os.path.normpath(directory))
            if (directory in manifests or not directory.is_relative_to(root)
                    or _excluded(root, workspace, directory)
                    or not os.path.lexists(directory / "Cargo.toml")):
                return
            manifests[directory] = _manifest(repo, directory / "Cargo.toml")
            for _, dependency in _manifest_path_dependencies(manifests[directory], directory, root, inherited):
                admit(dependency)

        for pattern in workspace.get("members") or []:
            if not isinstance(pattern, str) or not pattern:
                continue  # Cargo rejects the manifest too.
            if os.path.isabs(pattern) or ".." in PurePosixPath(pattern).parts:
                raise RepositoryRefusal(
                    f"refusing workspace member {pattern!r} in {root / 'Cargo.toml'}: hangover reads only manifests "
                    "inside the repository, so a member pattern may be neither absolute nor contain '..'")
            try:
                matches = sorted(root.glob(pattern))
            except (ValueError, NotImplementedError) as exc:
                raise RepositoryRefusal(f"refusing workspace member {pattern!r} in {root / 'Cargo.toml'}: {exc}") from exc
            for match in matches:
                admit(match)
        if root in manifests:
            for _, dependency in _manifest_path_dependencies(root_manifest, root, root, inherited):
                admit(dependency)
    if manifest_dir not in manifests and manifest_dir != root:
        raise RuntimeError(f"current package believes it's in a workspace when it's not: {manifest_dir / 'Cargo.toml'} "
                           f"is not a member of the workspace at {root / 'Cargo.toml'} (cargo refuses this layout)")
    for directory, manifest in manifests.items():
        if directory == root:
            continue
        if _workspace_table(manifest) is not None:
            raise RuntimeError(f"multiple workspace roots found in the same workspace: {directory} and {root} "
                               "(cargo refuses this layout)")
        named = _explicit_root(manifest, directory)
        if named is not None and named != root:
            raise RuntimeError(f"{directory / 'Cargo.toml'} names {named} as its workspace root, but it is a member "
                               f"of the workspace at {root} (cargo refuses this layout)")
    packages: dict[str, dict[str, Any]] = {}
    for directory, manifest in sorted(manifests.items()):
        package = manifest.get("package")
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            continue
        try:
            relative = directory.relative_to(repo).as_posix()
        except ValueError:
            continue
        library = manifest.get("lib") if isinstance(manifest.get("lib"), dict) else None
        proc_macro = bool(library and (library.get("proc-macro") or library.get("proc_macro")))
        has_library = library is not None or (package.get("autolib") is not False and (directory / "src/lib.rs").is_file())
        crate_types = set((library or {}).get("crate-type") or (library or {}).get("crate_type") or ["lib"])
        publish = package.get("publish", True)
        if isinstance(publish, dict) and publish.get("workspace") is True:
            publish = inherited_package.get("publish", True)
        packages[package["name"]] = {
            "name": package["name"],
            "dir": "" if relative == "." else relative,
            "manifest": (PurePosixPath(relative) / "Cargo.toml").as_posix() if relative != "." else "Cargo.toml",
            "lib": has_library and not proc_macro and bool(crate_types & LIBRARY_ROLES),
            "proc_macro": has_library and proc_macro,
            "publishable": publish is not False and publish != [],
            "path_dependencies": sorted({name for name, _ in _manifest_path_dependencies(
                manifest, directory, root, inherited)}),
        }
    refusal = _option_like(packages)
    if refusal:
        raise RepositoryRefusal(refusal)
    return {"root": str(root), "target_directory": None, "packages": _link_packages(packages)}


def _static_metadata(repo: Path, manifest_dir: Path) -> tuple[dict[str, Any], dict[str, Any] | None]:
    started = time.monotonic()
    command: dict[str, Any] = {"status": "completed", "exit_code": None, "command": None,
                               "source": "Cargo.toml files read directly; cargo was not run"}
    try:
        workspace = _static_workspace(repo, manifest_dir)
    except RuntimeError as exc:
        command.update(status="failed", error=str(exc), **({"refused": True} if isinstance(exc, RepositoryRefusal) else {}))
        workspace = None
    command["duration_seconds"] = round(time.monotonic() - started, 3)
    return command, workspace


def _matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def _role(relative_to_package: str) -> str:
    first = relative_to_package.split("/", 1)[0]
    if first in {"tests", "benches"}:
        return "test"
    if first == "examples":
        return "example"
    if relative_to_package == "build.rs":
        return "build"
    if relative_to_package == "src/main.rs" or relative_to_package.startswith("src/bin/"):
        return "bin"
    return "lib"


def _files(repo: Path, workspace: dict[str, Any], exclude: list[str],
           listed: list[Path]) -> dict[str, dict[str, Any]]:
    packages = sorted(workspace["packages"].values(), key=lambda item: -len(item["dir"]))
    files: dict[str, dict[str, Any]] = {}
    for path in listed:
        if path.suffix != ".rs":
            continue
        if not path.is_relative_to(repo):
            raise RepositoryRefusal(f"refusing the file list: {path} is not inside {repo}")
        relative = path.relative_to(repo).as_posix()
        if _matches(relative, exclude):
            continue
        owner = next((package for package in packages
                      if not package["dir"] or relative.startswith(package["dir"] + "/")), None)
        if owner is None:
            continue  # Not part of the Cargo workspace (an excluded crate, a fixture).
        inner = relative[len(owner["dir"]) + 1:] if owner["dir"] else relative
        try:
            text = read_repo_file(repo, relative, purpose=f"Rust source {relative!r}", errors="replace")
        except OSError:
            continue
        if text is None:
            continue
        files[relative] = {"package": owner["name"], "role": _role(inner), "text": text,
                           "lines": text.splitlines(), "test_ranges": []}
    return files


# --------------------------------------------------------------------------- items (ast-grep)

AST_GREP_RULES = [
    ("fn", "function_item", "name"),
    ("impl", "impl_item", "type"),
    ("mod", "mod_item", "name"),
    *[(kind, node, "name") for kind, node in ITEM_KINDS.items()],
]
# ast-grep reads exactly the files hangover checked (`files`), each named after `--`: it walks no
# directory, so a file hangover skipped (a hard link to a file outside the checkout, say) is never
# opened, and no path reads as an option. ast-grep 0.50 reads a path it is given whatever an ignore
# file says; the --no-ignore options keep it so should a later one filter given paths (no .gitignore,
# .ignore, .git/info/exclude or core.excludesFile hides a listed file). The paths go in chunks of
# AST_GREP_ARGUMENT_BYTES, well under any command-line limit; ast-grep's raw output stays outside
# the checkout, and only its lines for listed files are kept in ast-grep.out.
AST_GREP_NO_IGNORE = tuple(part for kind in ("hidden", "dot", "exclude", "global", "parent", "vcs")
                           for part in ("--no-ignore", kind))
AST_GREP_ARGUMENT_BYTES = 64 * 1024
GITHUB_LINE = re.compile(r"^::\w+ (?P<props>.*?)::(?P<message>.*)$")


def _argument_chunks(arguments: list[str], limit: int = AST_GREP_ARGUMENT_BYTES) -> list[list[str]]:
    """`arguments` in order, split so each chunk's bytes (each with its NUL and argv pointer) stay within `limit`."""
    chunks: list[list[str]] = []
    size = 0
    for argument in arguments:
        cost = len(os.fsencode(argument)) + 9
        if not chunks or size + cost > limit:
            chunks.append([])
            size = 0
        chunks[-1].append(argument)
        size += cost
    return chunks


def _ast_grep_rules() -> str:
    """One rule per item kind; the GitHub output format gives each match's span and name in one short line."""
    return "---\n".join(
        f"id: {rule_id}\nlanguage: rust\nseverity: info\nmessage: \"$NAME\"\n"
        f"rule:\n  kind: {kind}\n  has:\n    field: {field}\n    pattern: $NAME\n"
        for rule_id, kind, field in AST_GREP_RULES
    )


def _unescape(value: str) -> str:
    for escaped, plain in (("%0D", "\r"), ("%0A", "\n"), ("%3A", ":"), ("%2C", ","), ("%25", "%")):
        value = value.replace(escaped, plain)
    return value


def _items(repo: Path, out_dir: Path, files: dict[str, dict[str, Any]], workspace: dict[str, Any],
           environment: dict[str, str]) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    binary = ast_grep_path()
    if binary is None:
        return {"status": "unavailable", "error": "ast-grep is not installed; run `npm ci` in the hangover checkout"}, {}
    rules, config = (out_dir / "ast-grep-rules.yml").resolve(), (out_dir / "sgconfig.yml").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    rules.write_text(_ast_grep_rules())
    # hangover's own project config, so ast-grep never discovers the repository's sgconfig.yml (its
    # rule and util directories, its custom languages, which are native libraries); `--` ends the
    # options, so a package directory can never be read as one.
    config.write_text("ruleDirs: []\n")
    stdout, stderr = out_dir / "ast-grep.out", out_dir / "ast-grep.err"
    options = [str(binary), "scan", "--config", str(config), "--custom-languages=ignore", *AST_GREP_NO_IGNORE,
               "--rule", str(rules), "--format", "github", "--"]
    chunks = _argument_chunks(sorted(files), AST_GREP_ARGUMENT_BYTES)
    if not chunks:  # Never a bare `ast-grep scan`: it would walk the working directory.
        stdout.write_text("")
        stderr.write_text("")
        return {"status": "completed", "exit_code": None, "command": None, "stdout": str(stdout),
                "stderr": str(stderr), "items": 0}, {}
    items: dict[str, list[dict[str, Any]]] = defaultdict(list)
    kept: list[str] = []
    errors: list[str] = []
    command: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="hangover-ast-grep-") as scratch:
        for index, chunk in enumerate(chunks):
            run = _run("ast-grep", [*options, *chunk], repo, Path(scratch) / str(index), environment, 600)
            command = command or run
            if run is not command:
                command["duration_seconds"] = round(command["duration_seconds"] + run["duration_seconds"], 3)
            try:
                errors.append(captured_text(Path(run["stderr"])) if run.get("stderr") else "")
            except (OSError, RuntimeError):
                pass
            if run["status"] != "completed":
                command = run
                break
            try:
                output = captured_text(Path(run["stdout"]))
            except (OSError, RuntimeError) as exc:
                command = {**run, "status": "invalid_output", "error": str(exc)}
                break
            for raw in output.splitlines():
                match = GITHUB_LINE.match(raw)
                if not match:
                    continue
                props = dict(part.split("=", 1) for part in match["props"].split(",") if "=" in part)
                path = PurePosixPath(_unescape(props.get("file", ""))).as_posix()
                if path.startswith("./"):
                    path = path[2:]
                if path not in files:
                    continue
                kept.append(raw)
                items[path].append({"kind": props.get("title"), "name": _unescape(match["message"]).strip(),
                                    "start": int(props["line"]), "end": int(props.get("endLine", props["line"]))})
    stdout.write_text("".join(f"{line}\n" for line in kept))
    stderr.write_text("".join(errors))
    command.update(stdout=str(stdout), stderr=str(stderr))
    if len(chunks) > 1:
        command["chunks"] = len(chunks)
    if command["status"] != "completed":
        return command, {}
    command["items"] = sum(len(values) for values in items.values())
    if not command["items"] and files:
        command.update(status="invalid_output", error="ast-grep reported no items for a workspace with Rust files")
    return command, dict(items)


def _attributes_above(lines: list[str], start: int) -> str:
    """The attribute and doc lines directly above a 1-based item line."""
    collected = []
    index = start - 2
    while index >= 0:
        stripped = lines[index].strip()
        if stripped.startswith(("#[", "#!", "///", "//!", "//")) or (collected and stripped.endswith(("]", ")")) and not stripped.endswith(";")):
            collected.append(stripped)
            index -= 1
            continue
        break
    return "\n".join(reversed(collected))


def _module_dir(path: str) -> PurePosixPath:
    """Where a file's child modules live: beside a mod.rs/lib.rs/main.rs, else in a directory named after it."""
    file = PurePosixPath(path)
    return file.parent if file.name in {"mod.rs", "lib.rs", "main.rs"} else file.parent / file.stem


def _mark_test_modules(files: dict[str, dict[str, Any]], items: dict[str, list[dict[str, Any]]]) -> None:
    """Record each file's inline `#[cfg(test)]` module spans, and give the files of an
    out-of-line `#[cfg(test)] mod name;` (and everything below them) the unit_test role."""
    test_dirs: list[str] = []
    for path, info in files.items():
        info["test_ranges"] = []
        for item in items.get(path, []):
            if item["kind"] != "mod" or not CFG_TEST.search(_attributes_above(info["lines"], item["start"])):
                continue
            head = info["lines"][item["start"] - 1] if 0 < item["start"] <= len(info["lines"]) else ""
            if item["start"] == item["end"] and head.rstrip().endswith(";"):
                module = _module_dir(path) / item["name"]
                test_dirs.append(module.as_posix())
                for candidate in (f"{module}.rs", f"{module}/mod.rs"):
                    if candidate in files:
                        files[candidate]["role"] = "unit_test"
            else:
                info["test_ranges"].append((item["start"], item["end"]))
    for path, info in files.items():
        if info["role"] == "lib" and any(path.startswith(directory + "/") for directory in test_dirs):
            info["role"] = "unit_test"


def _annotate(files: dict[str, dict[str, Any]], items: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Mark test regions, qualify functions with their impl or trait, and read visibility."""
    functions: list[dict[str, Any]] = []
    _mark_test_modules(files, items)
    for path, info in files.items():
        entries = items.get(path, [])
        lines = info["lines"]
        test_ranges = info["test_ranges"]
        containers = [item for item in entries if item["kind"] in {"impl", "trait"}]
        for item in entries:
            head = lines[item["start"] - 1] if 0 < item["start"] <= len(lines) else ""
            visibility = (VISIBILITY.match(head) or [None, None])[1]
            item["visibility"] = re.sub(r"\s+", "", visibility) if visibility else None
            attributes = _attributes_above(lines, item["start"])
            item["exported"] = bool(EXPORT_ATTRIBUTE.search(attributes))
            item["test"] = (info["role"] in TEST_ROLES
                            or any(start <= item["start"] <= end for start, end in test_ranges)
                            or bool(TEST_ATTRIBUTE.search(attributes)))
            if item["kind"] != "fn":
                continue
            owner = min((container for container in containers
                         if container["start"] < item["start"] and item["end"] <= container["end"]),
                        key=lambda container: container["end"] - container["start"], default=None)
            item["trait_method"] = bool(owner and owner["kind"] == "trait")
            owner_name = re.split(r"[<\s]", owner["name"].lstrip("&").replace("mut ", ""), maxsplit=1)[0] if owner else ""
            item["qualname"] = f"{owner_name}::{item['name']}" if owner_name else item["name"]
            item["path"] = path
            functions.append(item)
    return functions


def _code_lines(lines: list[str], ranges: list[tuple[int, int]]) -> int:
    """Non-blank, non-comment-only lines outside the given 1-based ranges."""
    skip = set()
    for start, end in ranges:
        skip.update(range(start, end + 1))
    count = 0
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if number not in skip and stripped and not stripped.startswith(("//", "/*", "*")):
            count += 1
    return count


# --------------------------------------------------------------------------- identifier index

LEXICAL = re.compile(
    r"//[^\n]*"                                 # line comments (doc comments too)
    r"|/\*"                                     # block comment start (nesting handled below)
    r"|b?r(?P<hashes>#*)\""                     # raw string start
    r"|b?\"(?:\\.|[^\"\\])*\""                  # string
    r"|b?'(?:\\.|[^'\\\n])'",                   # char literal (a lifetime never matches)
    re.S,
)
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def strip_comments(text: str) -> str:
    """Rust source with comments blanked (newlines kept); string contents stay, since a
    name inside a string (a serde `with = "path"`, say) can be a real use."""
    parts: list[str] = []
    position = 0
    while True:
        match = LEXICAL.search(text, position)
        if not match:
            parts.append(text[position:])
            break
        token = match.group(0)
        start = match.start()
        if token.startswith("//"):
            parts.append(text[position:start])
            position = match.end()
        elif token == "/*":
            parts.append(text[position:start])
            depth, index = 1, match.end()
            while depth and index < len(text):
                if text.startswith("/*", index):
                    depth, index = depth + 1, index + 2
                elif text.startswith("*/", index):
                    depth, index = depth - 1, index + 2
                else:
                    index += 1
            parts.append("\n" * text.count("\n", start, index))
            position = index
        elif match.group("hashes") is not None and token.endswith('"') and "r" in token[:2]:
            closing = '"' + match.group("hashes")
            end = text.find(closing, match.end())
            end = len(text) if end < 0 else end + len(closing)
            parts.append(text[position:end])
            position = end
        else:
            parts.append(text[position:match.end()])
            position = match.end()
    return "".join(parts)


def _index(files: dict[str, dict[str, Any]]) -> dict[str, Counter[tuple[str, str]]]:
    """name -> Counter of (package, scope): scope `lib` is the package's library code
    outside test modules; `inner` its test modules; `outer` its bins, tests and examples."""
    index: dict[str, Counter[tuple[str, str]]] = defaultdict(Counter)
    for info in files.values():
        lines = strip_comments(info["text"]).split("\n")
        tests = sorted(info["test_ranges"])
        segments: list[tuple[str, list[str]]] = []
        if info["role"] == "unit_test":
            segments.append(("inner", lines))
        elif info["role"] != "lib":
            segments.append(("outer", lines))
        else:
            cursor = 1
            for start, end in tests:
                if start > cursor:
                    segments.append(("lib", lines[cursor - 1:start - 1]))
                segments.append(("inner", lines[max(start, cursor) - 1:end]))
                cursor = max(cursor, end + 1)
            segments.append(("lib", lines[cursor - 1:]))
        package = info["package"]
        for scope, chunk in segments:
            for name, count in Counter(IDENTIFIER.findall("\n".join(chunk))).items():
                index[name][(package, scope)] += count
    return index


# --------------------------------------------------------------------------- clippy


def _owned_directory(base: Path, *parts: str) -> Path:
    """base/parts..., creating each part as a private directory; refuses a symlink or non-directory on the way."""
    if base.is_symlink():
        raise RuntimeError(f"refusing {base}: it is a symlink")
    base.mkdir(parents=True, exist_ok=True)
    current = base
    for part in parts:
        current = current / part
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        if current.is_symlink() or not current.is_dir():
            raise RuntimeError(f"refusing {current}: hangover creates this directory itself, and it is a symlink "
                               "or not a directory")
    return current


def _clippy_config_dir(repo: Path, conf_root: Path, thresholds: dict[str, int]) -> Path:
    """The repository's clippy.toml with hangover's three thresholds in its place, in hangover's own state.

    The directory is named by the content, so an unchanged policy keeps the same CLIPPY_CONF_DIR
    (a new one makes clippy re-lint the workspace) and a file there is never rewritten in place.
    It lives under hangover's state (`conf_root`), never in the build tree, whose location and
    contents the repository controls; nothing is written through a link.
    """
    text = ""
    for name in ("clippy.toml", ".clippy.toml"):
        found = read_repo_file(repo, name, purpose=name)
        if found is not None:
            text = found
            break
    keys = set(CLIPPY_THRESHOLD_KEYS.values())
    kept = [line for line in text.splitlines() if line.split("=", 1)[0].strip() not in keys]
    kept += [f"{CLIPPY_THRESHOLD_KEYS[key]} = {thresholds[key]}" for key in CLIPPY_THRESHOLD_KEYS]
    content = "\n".join(kept) + "\n"
    directory = _owned_directory(conf_root, "rust-clippy-conf", digest(content)[:16])
    config = directory / "clippy.toml"
    if config.is_symlink() or (config.exists() and not config.is_file()):
        raise RuntimeError(f"refusing {config}: it is a symlink or not a file")
    if not config.is_file() or config.read_text() != content:
        descriptor, temporary = tempfile.mkstemp(prefix=".clippy.toml.", dir=directory)
        try:
            with os.fdopen(descriptor, "w") as handle:
                handle.write(content)
            os.replace(temporary, config)  # Replaces a directory entry; never opens what one points to.
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return directory


def hangover_target_dir(workspace: dict[str, Any], repo: Path) -> Path:
    """hangover's own target directory, beside the workspace's, so its lint flags never
    invalidate the gate's clippy cache (and the gate never invalidates hangover's)."""
    override = os.environ.get("HANGOVER_CARGO_TARGET_DIR")
    if override:
        return Path(override).expanduser().resolve()
    base = workspace.get("target_directory") or str(repo / "target")
    return Path(base) / "hangover"


def _clippy(repo: Path, out_dir: Path, workspace: dict[str, Any], policy: dict[str, Any],
            environment: dict[str, str], target: Path, *, conf_root: Path,
            manifest_dir: Path | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        conf_dir = _clippy_config_dir(manifest_dir or repo, conf_root, policy["thresholds"])
    except (OSError, RuntimeError) as exc:
        return {"status": "failed", "exit_code": None, "command": None,
                "error": f"could not write hangover's clippy configuration: {exc}"}, []
    environment = {**environment, "CLIPPY_CONF_DIR": str(conf_dir)}
    command = _run("cargo-clippy",
                   ["cargo", "clippy", *policy["clippy_args"], "--message-format=json", "--keep-going",
                    "--target-dir", str(target), "--", *LINT_FLAGS],
                   manifest_dir or repo, out_dir, environment, 7200, ok_codes=(0, 101))
    if command["status"] != "completed":
        return command, []
    root = Path(workspace["root"])
    messages: dict[tuple[Any, ...], dict[str, Any]] = {}
    hard_errors: list[str] = []
    failed_libraries: set[str] = set()
    other_lints: Counter[str] = Counter()
    for raw in captured_text(Path(command["stdout"])).splitlines():
        try:
            record = json.loads(raw)
        except ValueError:
            continue
        if record.get("reason") != "compiler-message":
            continue
        message = record.get("message") or {}
        code = (message.get("code") or {}).get("code")
        level = message.get("level")
        kinds = set((record.get("target") or {}).get("kind") or [])
        if level == "error" and kinds - {"bin", "test", "example", "bench", "custom-build"}:
            # A library that failed (even on a deny-level lint) stops cargo before its dependents.
            failed_libraries.add(str((record.get("target") or {}).get("name")))
        if level == "error" and (code is None or re.fullmatch(r"E\d{4}", code)):
            text = str(message.get("message", ""))
            if not text.startswith("aborting due to"):
                hard_errors.append(text)
            continue
        if code not in COMPLEXITY_LINTS and code not in DEAD_CODE_LINTS:
            if code:
                other_lints[f"{level} {code}"] += 1
            continue
        span = next((item for item in message.get("spans") or [] if item.get("is_primary")), None)
        if not span:
            continue
        try:
            path = (root / span["file_name"]).resolve().relative_to(repo.resolve()).as_posix()
        except ValueError:
            continue  # A span in a dependency or a generated file.
        key = (code, path, span.get("line_start"), span.get("column_start"), message.get("message"))
        messages.setdefault(key, {"lint": code, "path": path, "line": span.get("line_start"),
                                  "message": str(message.get("message", "")), "level": level})
    if hard_errors:
        command["status"] = "partial"
        command["error"] = (f"{len(hard_errors)} compile error(s); crates that failed to compile were not "
                            f"linted: {hard_errors[0][:300]}")
    elif failed_libraries:
        command["status"] = "partial"
        command["error"] = (f"library crate(s) {', '.join(sorted(failed_libraries))} failed with error-level "
                            "diagnostics, so the crates depending on them were not linted")
    if command["exit_code"] == 101 and not hard_errors and not other_lints and not messages:
        command["status"] = "failed"
        command["error"] = command.get("error") or "cargo clippy failed without compiler messages: " + diagnostic_text(
            "", command.get("stderr_tail", ""))
    command["other_lints"] = dict(sorted(other_lints.items()))
    return command, sorted(messages.values(), key=lambda item: (item["path"], item["line"] or 0, item["lint"]))


# --------------------------------------------------------------------------- jscpd


def _dupes(repo: Path, out_dir: Path, workspace: dict[str, Any], files: dict[str, dict[str, Any]],
           policy: dict[str, Any], environment: dict[str, str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    binary = jscpd_path()
    if binary is None:
        return {"status": "unavailable", "error": "jscpd is not installed; run `npm ci` in the hangover checkout"}, []
    report_dir = out_dir / "jscpd"
    if not files:
        return {"status": "completed", "exit_code": None, "command": None, "note": "no Rust files to compare"}, []
    # jscpd reads exactly hangover's file set, named by absolute path in its config (no argv limit, and
    # no name can read as an option): no .gitignore hides a tracked file (`--no-gitignore`; jscpd
    # 5.4.1 ignores the config's `gitignore` key, set false all the same), and no copy under
    # `target` or hangover's own audit tree is compared, where a clone's other half would be dropped
    # and the clone lost with it. No --ignore: jscpd matches globs against absolute paths, so a
    # checkout under any `.hangover` or `target` directory would vanish.
    thresholds = policy["thresholds"]
    # Given a config file, jscpd reads no other: never the repository's .jscpd.json or package.json
    # key, which could turn on semantic mode (source sent to an embeddings URL), history or other
    # analyses, or change what counts as a clone outside the policy digest.
    out_dir.mkdir(parents=True, exist_ok=True)
    config = (out_dir / "jscpd-config.json").resolve()
    top = repo.resolve()
    write_json(config, {"format": ["rust"], "minTokens": thresholds["clone_tokens"],
                        "minLines": thresholds["clone_lines"], "gitignore": False, "absolute": True,
                        "semantic": {"enabled": False}, "path": [str(top / path) for path in sorted(files)]})
    command = _run("jscpd", [str(binary), "--config", str(config), "--format", "rust",
                             "--min-tokens", str(thresholds["clone_tokens"]),
                             "--min-lines", str(thresholds["clone_lines"]), "--reporters", "json",
                             "--output", str(report_dir), "--silent", "--absolute", "--no-tips", "--no-gitignore"],
                   repo, out_dir, environment, 1200)
    if command["status"] != "completed":
        return command, []
    try:
        report = json.loads((report_dir / "jscpd-report.json").read_text())
    except (OSError, ValueError) as exc:
        command.update(status="invalid_output", error=f"jscpd wrote no readable JSON report: {exc}")
        return command, []
    parent: dict[tuple[str, int, int], tuple[str, int, int]] = {}

    def find(node: tuple[str, int, int]) -> tuple[str, int, int]:
        while parent.setdefault(node, node) != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    pairs = []
    for duplicate in report.get("duplicates") or []:
        spans = []
        for side in ("firstFile", "secondFile"):
            entry = duplicate.get(side) or {}
            try:
                path = Path(entry["name"]).resolve().relative_to(repo.resolve()).as_posix()
            except (KeyError, ValueError):
                break
            if path not in files:
                break
            spans.append((path, int((entry.get("startLoc") or {}).get("line", entry.get("start", 0))),
                          int((entry.get("endLoc") or {}).get("line", entry.get("end", 0)))))
        if len(spans) != 2:
            continue
        parent[find(spans[0])] = find(spans[1])
        pairs.append((spans, duplicate))
    groups: dict[tuple[str, int, int], dict[str, Any]] = {}
    for spans, duplicate in pairs:
        group = groups.setdefault(find(spans[0]), {"spans": set(), "lines": 0, "tokens": 0, "fragments": set()})
        group["spans"].update(spans)
        group["lines"] = max(group["lines"], int(duplicate.get("lines") or 0))
        group["tokens"] = max(group["tokens"], int(duplicate.get("tokens") or 0))
        fragment = duplicate.get("fragment")
        if isinstance(fragment, str):
            group["fragments"].add(" ".join(fragment.split()))
    result = []
    for group in groups.values():
        spans = sorted(group["spans"])
        result.append({"spans": spans, "lines": group["lines"], "tokens": group["tokens"],
                       "fingerprint": digest(sorted(group["fragments"]) or spans)[:16],
                       "fragment": min(group["fragments"], key=len) if group["fragments"] else ""})
    command["clone_pairs"] = len(pairs)
    command["statistics"] = (report.get("statistics") or {}).get("total", {})
    return command, sorted(result, key=lambda item: item["spans"])


# --------------------------------------------------------------------------- cargo-machete

MACHETE_HEADER = re.compile(r"^(?P<package>\S+) -- (?P<manifest>.+Cargo\.toml):\s*$")


def _machete(repo: Path, manifest_dir: Path, out_dir: Path,
            environment: dict[str, str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not shutil.which("cargo-machete", path=environment.get("PATH")):
        return {"status": "unavailable",
                "error": "cargo-machete is not installed (`cargo install cargo-machete`); unused dependencies are not analyzed"}, []
    command = _run("cargo-machete", ["cargo", "machete", "."], manifest_dir, out_dir, environment, 900,
                   ok_codes=(0, 1))
    if command["status"] != "completed":
        return command, []
    unused = []
    current: tuple[str, str] | None = None
    for line in captured_text(Path(command["stdout"])).splitlines():
        header = MACHETE_HEADER.match(line.strip())
        if header:
            manifest = Path(header["manifest"].strip())
            manifest = manifest if manifest.is_absolute() else manifest_dir / manifest
            try:
                current = (header["package"], manifest.resolve().relative_to(repo.resolve()).as_posix())
            except ValueError:
                current = None
            continue
        if current and line.startswith(("\t", "  ")) and line.strip() and " " not in line.strip():
            unused.append({"package": current[0], "manifest": current[1], "dependency": line.strip()})
        else:
            current = None
    if command["exit_code"] == 1 and not unused:
        command.update(status="invalid_output", error="cargo-machete reported unused dependencies hangover could not parse")
    return command, unused


# --------------------------------------------------------------------------- churn


def _churn(repo: Path, files: dict[str, dict[str, Any]], window_days: int = 180,
           revision: str = "HEAD") -> dict[str, Any]:
    """Commits per file over the window ending at the revision's commit time (reproducible per commit)."""
    quiet = ("--no-show-signature", "--no-ext-diff", "--no-textconv", "--no-color")
    head = _git(repo, "log", "-1", *quiet, "--format=%ct", revision, "--")
    if head.returncode != 0 or not head.stdout.strip().isdigit():
        return {"status": "unavailable", "error": f"no {revision} commit", "commits": {}}
    anchor = int(head.stdout.strip())
    since = datetime.fromtimestamp(anchor - window_days * 86400, timezone.utc).isoformat()
    result = _git(repo, "log", "--no-merges", *quiet, f"--since={since}", "--format=%x00", "--name-only",
                  revision, "--", "*.rs")
    if result.returncode != 0:
        return {"status": "failed", "error": f"git log exited {result.returncode}", "commits": {}}
    counts: Counter[str] = Counter()
    for block in result.stdout.split("\0"):
        for name in {line.strip() for line in block.splitlines() if line.strip()}:
            if name in files:
                counts[name] += 1
    ranked = [count for count in sorted(counts.values(), reverse=True)]
    cutoff = max(5, ranked[max(0, len(ranked) // 10 - 1)]) if ranked else 0
    hot = sorted(path for path, count in counts.items() if count >= cutoff) if ranked else []
    return {"status": "completed", "window_days": window_days, "anchor": anchor, "cutoff": cutoff,
            "commits": dict(counts), "hotspots": hot}


# --------------------------------------------------------------------------- findings


def finding_key(category: str, *parts: str) -> str:
    return ":".join([category, *parts])


def _finding(category: str, parts: list[str], *, title: str, evidence: list[str], files: list[str],
             symbols: list[str], priority: str, risk: str, confidence: str,
             chesterton: str, invariants: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    key = finding_key(category, *parts)
    return {
        "fingerprint": ["rust", category, *parts],
        "source": "rust",
        "source_version": f"hangover-rust {RUST_ANALYSIS_VERSION}",
        "category": category,
        "title": title,
        "suppression": {"config_key": "ignore", "value": key, "file": POLICY_FILE},
        "evidence": evidence,
        "files": files,
        "symbols": symbols,
        "harm": HARM[category],
        "proposed_change": CHANGE[category],
        "invariants": invariants or ["Every caller observes identical inputs, outputs, side effects, and error behavior.",
                                     "Public and serialization contracts remain compatible."],
        "risk": risk,
        "priority": priority,
        "confidence": confidence,
        "verification": VERIFY.get(category, VERIFY["default"]),
        "chesterton": chesterton,
        **extra,
    }


def _bump(priority: str) -> str:
    return {"P3": "P2", "P2": "P1"}.get(priority, priority)


def _ratio_priority(ratio: float, *, cap: str = "P1") -> str:
    priority = "P1" if ratio >= 3 else "P2" if ratio >= 2 else "P3"
    return max(priority, cap)  # "P2" > "P1": the cap is the most urgent allowed.


def _hotspot_note(path: str, churn: dict[str, Any]) -> str | None:
    commits = (churn.get("commits") or {}).get(path)
    if path in set(churn.get("hotspots") or []):
        return (f"Hotspot: {commits} commits in the {churn.get('window_days')} days before HEAD "
                f"(top tier, cutoff {churn.get('cutoff')}); priority raised one level.")
    return None


def _complexity_findings(messages: list[dict[str, Any]], functions: list[dict[str, Any]],
                         thresholds: dict[str, int], churn: dict[str, Any]) -> list[dict[str, Any]]:
    by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for function in functions:
        by_path[function["path"]].append(function)
    measured: dict[tuple[str, int], dict[str, Any]] = {}
    for message in messages:
        metric = COMPLEXITY_LINTS.get(message["lint"])
        if not metric:
            continue
        values = re.search(r"\((\d+)/(\d+)\)", message["message"])
        line = message["line"] or 0
        function = min((item for item in by_path.get(message["path"], []) if item["start"] <= line <= item["end"]),
                       key=lambda item: item["end"] - item["start"], default=None)
        start = function["start"] if function else line
        entry = measured.setdefault((message["path"], start), {"function": function, "line": line, "metrics": {}})
        if values:
            entry["metrics"][metric] = int(values[1])
    occurrences: Counter[tuple[str, str]] = Counter()
    findings = []
    limits = {"cognitive": thresholds["cognitive"], "line_count": thresholds["function_lines"],
              "arguments": thresholds["arguments"]}
    for (path, start), entry in sorted(measured.items()):
        function = entry["function"]
        name = function["qualname"] if function else f"function at line {entry['line']}"
        occurrences[(path, name)] += 1
        identity = name if occurrences[(path, name)] == 1 else f"{name}#{occurrences[(path, name)]}"
        metrics = entry["metrics"]
        ratio = max((metrics[key] / limits[key] for key in metrics), default=1.0)
        test = bool(function and function["test"])
        priority = "P3" if test else _ratio_priority(ratio)
        evidence = ["clippy measured " + ", ".join(
            f"{label} {metrics[key]} (threshold {limits[key]})"
            for key, label in (("cognitive", "cognitive complexity"), ("line_count", "lines"), ("arguments", "arguments"))
            if key in metrics) + f" for {name} in {path}:{start}."]
        if test:
            evidence.append("Test code: kept at P3; simplify only where the test's intent is obscured.")
        else:
            note = _hotspot_note(path, churn)
            if note:
                priority = _bump(priority)
                evidence.append(note)
        evidence.append("In-source waiver clippy honors: #[expect(clippy::<lint>, reason = \"...\")] on the function.")
        findings.append(_finding(
            "complexity", [path, identity],
            title=f"Reduce complexity of {name} in {path}", evidence=evidence, files=[path], symbols=[name],
            priority=priority, risk="medium", confidence="high",
            chesterton="High complexity sometimes encodes essential domain policy; identify which branches are essential before extracting or collapsing any of them.",
            invariants=["Every caller observes identical inputs, outputs, side effects, and error behavior.",
                        "No test is weakened or deleted to make the refactor pass."],
            complexity_metrics={**metrics, **{f"max_{key}": limits[key] for key in limits}},
        ))
    return findings


def _lint_findings(messages: list[dict[str, Any]], files: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    occurrences: Counter[tuple[str, str, str]] = Counter()
    for message in messages:
        category = DEAD_CODE_LINTS.get(message["lint"])
        if not category:
            continue
        text = message["message"]
        occurrences[(category, message["path"], text)] += 1
        count = occurrences[(category, message["path"], text)]
        identity = text if count == 1 else f"{text}#{count}"
        info = files.get(message["path"], {})
        test = info.get("role") in TEST_ROLES or any(
            start <= (message["line"] or 0) <= end for start, end in info.get("test_ranges", []))
        findings.append(_finding(
            category, [message["path"], identity],
            title=f"{text} ({message['path']})",
            evidence=[f"rustc/clippy `{message['lint']}` at {message['path']}:{message['line']}: {text}.",
                      "Proven for the targets and features hangover builds (policy clippy_args); code used only "
                      "under another cfg or feature looks unused here."],
            files=[message["path"]], symbols=re.findall(r"`([^`]+)`", text),
            priority="P3" if test else ("P1" if category == "dead_code" else "P2"),
            risk="low", confidence="high",
            chesterton="Check other cfg targets, features and platforms before deleting: the compiler only saw this build.",
        ))
    return findings


def _pub_findings(files: dict[str, dict[str, Any]], items: dict[str, list[dict[str, Any]]],
                  workspace: dict[str, Any], thresholds: dict[str, int]) -> list[dict[str, Any]]:
    packages = workspace["packages"]
    index = _index(files)
    unused: list[dict[str, Any]] = []
    local: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    surface: Counter[str] = Counter()
    surface_files: dict[str, Counter[str]] = defaultdict(Counter)
    # A library with no consumer outside itself (no workspace dependent, no own binary,
    # integration test or example) makes every pub item "crate-local": nothing to narrow for.
    consumed = {name for name, package in packages.items() if package["dependents"]} | {
        info["package"] for info in files.values() if info["role"] in {"bin", "test", "example"}}
    for path, info in files.items():
        package = packages[info["package"]]
        if info["role"] != "lib" or not package["lib"] or package["proc_macro"]:
            continue
        for item in items.get(path, []):
            if (item["kind"] in {"impl", "mod"} or item["visibility"] != "pub" or item["test"] or item["exported"]
                    or item.get("trait_method") or item["name"] == "main"):
                continue
            counts = index.get(item["name"], Counter())
            total = sum(counts.values())
            outside = sum(count for (owner, scope), count in counts.items()
                          if owner != package["name"] or scope == "outer")
            surface[package["name"]] += 1
            surface_files[package["name"]][path] += 1
            if total <= 1:
                unused.append({"path": path, "item": item, "package": package["name"]})
            elif outside == 0 and not package["publishable"] and package["name"] in consumed:
                local[package["name"]][path].append(item["name"])
    findings = []
    for entry in unused:
        item, path = entry["item"], entry["path"]
        publishable = packages[entry["package"]]["publishable"]
        findings.append(_finding(
            "unused_pub_items", [path, item["kind"], item["name"]],
            title=f"Unused pub {item['kind']} {item['name']} in {path}",
            evidence=[f"`pub {item['kind']} {item['name']}` ({path}:{item['start']}) is named nowhere else in the "
                      "workspace (comments excluded, string contents included).",
                      *(["The crate is publishable, so users outside this workspace may call it."] if publishable else []),
                      "Macro-built names, generated code and other repositories are invisible to this index; "
                      "the compiler rejects a deletion any workspace target still needs."],
            files=[path], symbols=[item["name"]], priority="P2" if publishable else "P1", risk="low",
            confidence="low" if publishable else "medium",
            chesterton="A public item can exist for FFI, a macro, a plugin or another repository; establish why it exists before removing it.",
        ))
    # One card per crate: whether a crate's helpers are its API is one decision, and narrowing file
    # by file fails to compile wherever a still-`pub` item exposes a narrowed one.
    for package, by_path in sorted(local.items()):
        names = sorted({name for values in by_path.values() for name in values})
        count = sum(len(values) for values in by_path.values())
        listed = [f"{path}: {', '.join(sorted(values))}" for path, values in sorted(by_path.items())]
        findings.append(_finding(
            "crate_local_pub", [package],
            title=f"Narrow {count} pub item(s) in crate {package} that no other crate uses",
            evidence=[f"{count} `pub` item(s) in {len(by_path)} file(s) of crate {package} are named only inside it "
                      "(not by its binaries, integration tests or any other workspace crate).",
                      *listed[:20], *([f"+{len(listed) - 20} more files"] if len(listed) > 20 else []),
                      "Narrow them together: one narrowed alone fails to compile while another `pub` item exposes it.",
                      "Glob imports of traits and macro-expanded paths can hide a use; the compiler rejects any narrowing a user needs."],
            files=sorted(by_path), symbols=names, priority="P3", risk="low", confidence="medium",
            chesterton="An item may be pub on purpose as an intended interface awaiting its user; ask before narrowing a deliberate API.",
            pub_items=names,
        ))
    for name, count in sorted(surface.items()):
        if count <= thresholds["pub_surface"]:
            continue
        top = surface_files[name].most_common(5)
        package = packages[name]
        findings.append(_finding(
            "wide_pub_surface", [name],
            title=f"Crate {name} exports {count} pub items",
            evidence=[f"Crate {name} declares {count} `pub` items in its library code (threshold {thresholds['pub_surface']}).",
                      "Largest contributors: " + ", ".join(f"{path} ({items})" for path, items in top) + ".",
                      f"Workspace dependents: {', '.join(package['dependents']) or 'none'}."],
            files=[package["manifest"]], symbols=[name], priority="P3", risk="medium", confidence="medium",
            chesterton="A wide surface may be a deliberate facade; establish the crate's intended consumers first.",
        ))
    return findings


def _size_findings(files: dict[str, dict[str, Any]], workspace: dict[str, Any], thresholds: dict[str, int],
                   churn: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings = []
    production: dict[str, int] = {}
    for path, info in files.items():
        if info["role"] in {"lib", "bin"}:
            production[path] = _code_lines(info["lines"], info["test_ranges"])
    for path, lines in sorted(production.items()):
        if lines <= thresholds["file_lines"]:
            continue
        info = files[path]
        test_lines = sum(end - start + 1 for start, end in info["test_ranges"])
        priority = _ratio_priority(lines / thresholds["file_lines"], cap="P2")
        evidence = [f"{path} has {lines} lines of production code (threshold {thresholds['file_lines']}); "
                    f"{len(info['lines'])} lines in all, {test_lines} in test modules."]
        note = _hotspot_note(path, churn)
        if note:
            priority = _bump(priority)
            evidence.append(note)
        findings.append(_finding(
            "god_file", [path], title=f"Split {path} ({lines} production lines)", evidence=evidence,
            files=[path], symbols=[], priority=priority, risk="medium", confidence="high",
            chesterton="A large file can be one cohesive state machine or table; find real seams before splitting.",
            size_metrics={"production_lines": lines, "threshold": thresholds["file_lines"]},
        ))
    packages = workspace["packages"]
    crate_lines: Counter[str] = Counter()
    module_lines: Counter[str] = Counter()
    for path, lines in production.items():
        package = packages[files[path]["package"]]
        crate_lines[package["name"]] += lines
        prefix = f"{package['dir']}/src" if package["dir"] else "src"
        parent = PurePosixPath(path).parent
        while parent.as_posix().startswith(prefix + "/"):
            module_lines[parent.as_posix()] += lines
            parent = parent.parent
    for directory, lines in sorted(module_lines.items()):
        if lines <= thresholds["module_lines"]:
            continue
        children = sorted(((path, count) for path, count in production.items()
                           if path.startswith(directory + "/")), key=lambda item: -item[1])[:5]
        findings.append(_finding(
            "oversized_module", [directory], title=f"Module {directory} holds {lines} production lines",
            evidence=[f"{directory} holds {lines} lines of production code (threshold {thresholds['module_lines']}).",
                      "Largest files: " + ", ".join(f"{path} ({count})" for path, count in children) + "."],
            files=[directory], symbols=[], priority="P3", risk="high", confidence="medium",
            chesterton="Size alone is not a boundary; split only along seams the code already has.",
            size_metrics={"production_lines": lines, "threshold": thresholds["module_lines"]},
        ))
    for name, lines in sorted(crate_lines.items()):
        if lines <= thresholds["crate_lines"]:
            continue
        package = packages[name]
        findings.append(_finding(
            "oversized_crate", [name], title=f"Crate {name} holds {lines} production lines",
            evidence=[f"Crate {name} holds {lines} lines of production code (threshold {thresholds['crate_lines']}).",
                      f"Workspace dependencies: {', '.join(package['path_dependencies']) or 'none'}; "
                      f"dependents: {', '.join(package['dependents']) or 'none'}."],
            files=[package["manifest"]], symbols=[name],
            priority=_ratio_priority(lines / thresholds["crate_lines"], cap="P2"), risk="high", confidence="medium",
            chesterton="A crate split changes build graphs and visibility; it is an architecture decision, not a cleanup.",
            size_metrics={"production_lines": lines, "threshold": thresholds["crate_lines"]},
        ))
    summary = {"production_lines": sum(production.values()), "crate_production_lines": dict(sorted(crate_lines.items()))}
    return findings, summary


def _duplication_findings(groups: list[dict[str, Any]], files: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for group in groups:
        paths = sorted({span[0] for span in group["spans"]})
        test = all(files[path]["role"] in TEST_ROLES or any(
            start <= span[1] <= end for start, end in files[path]["test_ranges"])
            for span in group["spans"] for path in [span[0]])
        locations = [f"{path}:{start}-{end}" for path, start, end in group["spans"]]
        if len(paths) == 1:
            where = f"repeated {len(group['spans'])} times within {paths[0]}"
        else:
            where = f"shared by {len(paths)} files ({', '.join(paths[:3])}{', +more' if len(paths) > 3 else ''})"
        excerpt = group["fragment"][:240]
        findings.append(_finding(
            "duplication", [group["fingerprint"]],
            title=f"Consolidate {group['lines']} duplicated lines {where}",
            evidence=[f"jscpd found {group['lines']} duplicated lines ({group['tokens']} tokens) across "
                      f"{len(group['spans'])} instances.", *[f"Instance: {item}" for item in locations],
                      f"Fragment (whitespace collapsed): {excerpt}",
                      "In-source waiver jscpd honors: // jscpd:ignore-start ... // jscpd:ignore-end."],
            files=paths, symbols=[], priority="P3" if test else "P2", risk="medium", confidence="medium",
            chesterton="Similar text can encode deliberately different policy; establish shared semantics before extracting.",
            invariants=["All callers retain their current inputs, outputs, and side effects."],
            duplication_identity={"spans": [{"file": path, "start_line": start, "end_line": end}
                                            for path, start, end in group["spans"]]},
        ))
    return findings


def _dependency_findings(unused: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_finding(
        "unused_dependencies", [entry["manifest"], entry["dependency"]],
        title=f"Unused dependency {entry['dependency']} in {entry['manifest']}",
        evidence=[f"cargo-machete found no use of `{entry['dependency']}` in crate {entry['package']}.",
                  "cargo-machete searches source text: a dependency used only by a macro expansion, a build "
                  "script or feature forwarding can look unused. Its own waiver is "
                  "[package.metadata.cargo-machete] ignored = [...] in the manifest."],
        files=[entry["manifest"]], symbols=[entry["dependency"]], priority="P1", risk="medium", confidence="medium",
        chesterton="A dependency can be load-bearing through a macro, a link-time side effect or a feature; check before removing.",
    ) for entry in unused]


# --------------------------------------------------------------------------- scan


NOT_EXECUTED = ("not run: this analysis never runs cargo, which would execute the repository's build "
                "scripts and proc macros (and the toolchain its rust-toolchain.toml names)")


def _not_applicable(repo: Path, listed: list[Path] | None = None) -> dict[str, Any]:
    notice = manifest_notice(repo, listed)
    return {"status": "not_applicable", "commands": {}, "findings": [], **({"notice": notice} if notice else {})}


def _policy_failure(error: RuntimeError) -> dict[str, Any]:
    """A scan that could not start: the repository's policy file is invalid, or refused (`refusal`)."""
    refused = {"refused": True} if isinstance(error, RepositoryRefusal) else {}
    return {"status": "failed", "version": f"hangover-rust {RUST_ANALYSIS_VERSION}", "tools": {}, "policy_sha256": None,
            "error": str(error), "sections": {"policy": "failed"}, **({"refusal": str(error)} if refused else {}),
            "commands": {"policy": {"status": "failed", "exit_code": None, "command": None, "error": str(error), **refused}},
            "warnings": [f"policy: failed — {error}"], "summary": {"findings": 0, "by_category": {}, "suppressed": 0},
            "findings": []}


def run_rust_scan(repo: Path, run_dir: Path, *, name: str = "rust", target_dir: Path | None = None,
                  policy: dict[str, Any] | None = None, progress: Any = None, execute: bool = True,
                  state_root: Path | None = None, listed: list[Path] | None = None,
                  history: tuple[Path, str] | None = None) -> dict[str, Any]:
    """Every Rust section, then the findings; never raises for a tool failure.

    execute=False is analysis that never executes repository code: no cargo, rustup or clippy at all.
    The workspace is read from the manifests, the source-reading sections (items, dupes, churn) run,
    and clippy and cargo-machete are `skipped`, so the result is `partial`. A not_applicable result
    carries `notice` when the repository holds a Cargo.toml hangover was not pointed at (`manifest_notice`).
    An invalid policy file is a `failed` result with its `policy` section naming the error; so is a
    file list naming a path outside the repository (`_listed_files`), with a `files` section.
    `state_root` is the hangover state directory that holds generated clippy configuration (default:
    this repository's own). `listed` is the tree's files and `history` the (repository, commit)
    churn is counted at; by default both come from repo's own git (an audit's base tree has no git
    of its own, and git is never run inside it). Given `history`, the tools run with git's
    discovery stopped at the tree (GIT_CEILING_DIRECTORIES), so a build script finds no repository.
    """
    repo = repo.resolve()
    if policy is None:
        try:
            policy = load_policy(repo)
        except RuntimeError as exc:
            return _policy_failure(exc)
    manifest_dir = _manifest_dir(repo, policy.get("root"))
    if manifest_dir is None:
        return _not_applicable(repo, listed)
    out_dir = run_dir / name
    environment = cargo_environment()
    if history is not None:
        # An audit's base tree has no git of its own and sits inside the repository, so a build script
        # running git there (`git rev-parse HEAD`, `git describe`) would read the current checkout,
        # not the base commit. Git may not search above the tree: it finds no repository at all, as
        # for a crate built from a registry download. A build script that opens ../.git by path still
        # reaches the checkout; nothing short of a separate clone would stop that.
        environment["GIT_CEILING_DIRECTORIES"] = str(repo.parent)
    commands: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []

    def step(label: str) -> None:
        if progress:
            progress(f"rust: {label}")

    if execute:
        step("cargo metadata")
        commands["metadata"], workspace = _workspace(repo, manifest_dir, out_dir, environment)
    else:
        step("workspace manifests (static: cargo is not run)")
        commands["metadata"], workspace = _static_metadata(repo, manifest_dir)
    skipped = {"status": "skipped", "exit_code": None, "command": None, "error": NOT_EXECUTED}
    target: Path | None = None
    findings: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    if workspace is not None:
        try:
            files = _files(repo, workspace, policy["exclude"], _listed_files(repo) if listed is None else listed)
        except RuntimeError as exc:  # The file list names a path outside the repository: nothing is read.
            commands["files"] = {"status": "failed", "exit_code": None, "command": None, "error": str(exc),
                                 **({"refused": True} if isinstance(exc, RepositoryRefusal) else {})}
            workspace = None
    if workspace is not None:
        step(f"items ({len(files)} files)")
        commands["items"], items = _items(repo, out_dir, files, workspace, environment)
        functions = _annotate(files, items) if commands["items"]["status"] == "completed" else []
        messages: list[dict[str, Any]] = []
        if execute:
            target = target_dir or hangover_target_dir(workspace, manifest_dir)
            step(f"cargo clippy (target {target})")
            commands["clippy"], messages = _clippy(repo, out_dir, workspace, policy, environment, target,
                                                   conf_root=state_root or paths(repo)["root"],
                                                   manifest_dir=manifest_dir)
        else:
            commands["clippy"] = dict(skipped)
        step("jscpd")
        commands["dupes"], groups = _dupes(repo, out_dir, workspace, files, policy, environment)
        unused_dependencies: list[dict[str, Any]] = []
        if execute:
            step("cargo machete")
            commands["machete"], unused_dependencies = _machete(repo, manifest_dir, out_dir, environment)
        else:
            commands["machete"] = dict(skipped)
        churn = _churn(history[0], files, revision=history[1]) if history else _churn(repo, files)
        commands["churn"] = {key: value for key, value in churn.items() if key != "commits"}
        if commands["clippy"]["status"] in {"completed", "partial"}:
            findings += _complexity_findings(messages, functions, policy["thresholds"], churn)
            findings += _lint_findings(messages, files)
        if commands["items"]["status"] == "completed":
            findings += _pub_findings(files, items, workspace, policy["thresholds"])
            size, summary = _size_findings(files, workspace, policy["thresholds"], churn)
            findings += size
        if commands["dupes"]["status"] == "completed":
            findings += _duplication_findings(groups, files)
        if commands["machete"]["status"] == "completed":
            findings += _dependency_findings(unused_dependencies)
        summary.update(files=len(files), packages=len(workspace["packages"]), functions=len(functions),
                       crate_graph={name: package["path_dependencies"] for name, package in sorted(workspace["packages"].items())},
                       target_dir=str(target) if target else None,
                       **({"root": policy["root"]} if policy.get("root") else {}))
        other = commands["clippy"].get("other_lints") or {}
        if other:
            warnings.append("clippy also reported (not hangover findings; the gate's concern): "
                            + ", ".join(f"{count} {lint}" for lint, count in other.items()))
    ignored = set(policy["ignore"])
    suppressed = [finding for finding in findings if finding["suppression"]["value"] in ignored]
    findings = [finding for finding in findings if finding["suppression"]["value"] not in ignored]
    for section, command in commands.items():
        if command.get("status") not in {"completed"} and section != "churn":
            warnings.append(f"{section}: {command.get('status')} — {command.get('error', 'no detail')}")
    sections = {section: command.get("status") for section, command in commands.items()}
    required_ok = all(sections.get(section) == "completed" for section in REQUIRED_SECTIONS)
    optional_ok = all(sections.get(section) in {"completed", "unavailable"} for section in ("machete",))
    status = "completed" if required_ok and optional_ok else "failed" if workspace is None else "partial"
    counts = Counter(finding["category"] for finding in findings)
    refusal = next((command["error"] for command in commands.values() if command.get("refused")), None)
    return {
        "status": status,
        "version": f"hangover-rust {RUST_ANALYSIS_VERSION}",
        "tools": tool_versions(manifest_dir, execute=execute),
        "policy_sha256": digest(policy),
        "sections": sections,
        "commands": commands,
        "warnings": warnings,
        "summary": {**summary, "findings": len(findings), "by_category": dict(sorted(counts.items())),
                    "suppressed": len(suppressed)},
        "findings": findings,
        **({"error": commands["files"]["error"]} if "files" in commands else {}),
        # hangover refused repository content (RepositoryRefusal): the CLI's scan and run exit as a tool error.
        **({"refusal": refusal} if refusal else {}),
    }


def extract_rust_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(finding) for finding in result.get("findings") or []]


def rust_comparison(baseline: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    """Whether this scan's Rust evidence can be compared with the baseline's."""
    after = current.get("rust") or {}
    if after.get("status") in {None, "not_applicable", "disabled"}:
        return {"comparable": True, "kind": "not_applicable"}
    if not baseline:
        return {"comparable": False, "kind": "no_baseline", "reason": "no baseline"}
    before = baseline.get("rust") or {}
    if before.get("status") in {None, "not_applicable", "disabled"}:
        return {"comparable": False, "kind": "no_baseline",
                "reason": "the baseline has no Rust analysis"}
    if before.get("version") != after.get("version"):
        return {"comparable": False, "kind": "version_changed", "reason": "hangover's Rust analysis version changed",
                "from": before.get("version"), "to": after.get("version")}
    # Which evidence exists comes before tool versions: a static scan (cargo skipped) against a full
    # one differs in both, and the missing sections are the reason that matters.
    available = lambda result: sorted(k for k, v in (result.get("sections") or {}).items()
                                      if v not in {"unavailable", "skipped"})
    if available(before) != available(after):
        return {"comparable": False, "kind": "sections_changed",
                "reason": f"available Rust sections changed ({', '.join(available(before))} -> {', '.join(available(after))})"}
    for field, label in (("tools", "Rust tool versions"), ("policy_sha256", f"{POLICY_FILE} policy")):
        if before.get(field) != after.get(field):
            return {"comparable": False, "kind": "version_changed" if field != "policy_sha256" else "config_changed",
                    "reason": f"{label} changed", "from": before.get(field), "to": after.get(field)}
    old, new = (before.get("summary") or {}).get("findings"), (after.get("summary") or {}).get("findings")
    changes = {"findings": {"baseline": old, "current": new, "delta": new - old, "direction": "lower"}} if isinstance(old, int) and isinstance(new, int) else {}
    return {"comparable": True, "kind": "comparable", "changes": changes}


# --------------------------------------------------------------------------- audit


AUDIT_DIR = "rust-audit"
EARLIER_BASE_WORKTREE = "rust-audit-base"


def run_rust_audit(repo: Path, run_dir: Path, base: str, progress: Any = None, *,
                   execute: bool = True) -> dict[str, Any]:
    """Findings this tree has that the base commit does not, by card identity.

    The base commit's tree is written from git objects into hangover's own directory,
    .hangover/rust-audit/tree, and never checked out: a checkout runs the repository's hooks and
    filters. The directory is kept between audits and synced in place, so a file the base did not
    change keeps its mtime and cargo stays incremental; it shares this tree's target directory.
    Git never runs inside it, and anything there hangover did not create is refused, never reused
    or removed.
    """
    repo = repo.resolve()
    current = run_rust_scan(repo, run_dir, name="rust", progress=progress, execute=execute)
    if current["status"] == "not_applicable":
        return {"status": "not_applicable", "verdict": None, **({"notice": current["notice"]} if current.get("notice") else {})}
    if "failed" in {(current.get("sections") or {}).get(section) for section in ("policy", "files")}:
        return {"status": "failed", "verdict": None, "current": _audit_view(current), "error": current.get("error"),
                **({"refusal": current["refusal"]} if current.get("refusal") else {})}
    warnings = _earlier_worktree_warning(repo)
    base_tree, commit, listed, error = _prepare_base_tree(repo, base)
    if base_tree is None or commit is None:
        return {"status": "failed", "verdict": None, "current": _audit_view(current), "error": error,
                **({"warnings": warnings} if warnings else {})}
    target = Path((current.get("summary") or {}).get("target_dir") or base_tree.parent / "target")
    if progress:
        progress(f"rust: analyzing base {base[:12]}")
    previous = run_rust_scan(base_tree, run_dir, name="rust-base", target_dir=target,
                             policy=load_policy(repo), progress=progress, execute=execute,
                             state_root=paths(repo)["root"], listed=listed, history=(repo, commit))
    from .model import issue_id  # Local import: model imports nothing from here.
    base_ids = {issue_id(finding) for finding in previous.get("findings") or []}
    introduced = [finding for finding in current.get("findings") or [] if issue_id(finding) not in base_ids]
    complete = current["status"] == "completed" and previous["status"] == "completed"
    # hangover refused repository content on either side (RepositoryRefusal): the CLI's audit exits 2.
    refusal = current.get("refusal") or previous.get("refusal")
    return {
        "status": "completed" if complete else "partial",
        "verdict": ("fail" if introduced else "pass") if complete else None,
        "introduced": [{"id": issue_id(finding), "category": finding["category"], "title": finding["title"],
                        "files": finding["files"], "priority": finding["priority"]} for finding in introduced],
        "current": _audit_view(current),
        "base": _audit_view(previous),
        **({"warnings": warnings} if warnings else {}),
        **({"refusal": refusal} if refusal else {}),
    }


def _earlier_worktree_warning(repo: Path) -> list[str]:
    try:
        earlier = paths(repo)["root"] / EARLIER_BASE_WORKTREE
    except RuntimeError:
        return []
    if not os.path.lexists(earlier):
        return []
    return [f"{earlier} is the base worktree earlier hangover versions kept; this version no longer uses or "
            f"touches it (`git worktree remove --force {earlier}` removes it)"]


def _prepare_base_tree(repo: Path, base: str) -> tuple[Path | None, str | None, list[Path], str | None]:
    """hangover's base tree holding base's files: (tree, commit, its files, None), or Nones and why not."""
    try:
        holder = _owned_directory(paths(repo)["root"], AUDIT_DIR)
    except (OSError, RuntimeError) as exc:
        return None, None, [], f"refusing the audit's base tree: {exc}"
    # A clone can put files at any path, hangover's state included; files git tracks there are not hangover's.
    tracked = _git(repo, "ls-files", "-z", "--", f":(literal){holder.relative_to(repo).as_posix()}")
    if tracked.returncode != 0:
        return None, None, [], f"could not list {holder}: {tracked.stderr.strip()[:300]}"
    if tracked.stdout:
        return None, None, [], (f"refusing {holder}: files there are tracked by the repository "
                                f"({tracked.stdout.split(chr(0))[0]}), and hangover only writes a directory it "
                                "created itself; remove them from the repository and retry")
    tree, owner = holder / "tree", holder / "tree.owner"
    if tree.is_symlink() or owner.is_symlink():
        return None, None, [], f"refusing {tree}: it is a symlink, and hangover writes only the directory it creates there"
    if os.path.lexists(tree) and not (tree.is_dir() and owner.is_file()):
        return None, None, [], (f"refusing {tree}: hangover did not create it, and never reuses or removes a "
                                "directory it did not create; move it away and retry")
    resolved = _git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{base}^{{commit}}")
    if resolved.returncode != 0 or not resolved.stdout.strip():
        return None, None, [], f"{base!r} is not a commit in this repository"
    commit = resolved.stdout.strip()
    try:
        if not tree.exists():
            owner.write_text("hangover writes .hangover/rust-audit/tree from git objects for audits; it may delete it.\n")
            tree.mkdir(mode=0o700)
        listed = _write_tree(repo, commit, tree)
    except (OSError, RuntimeError, ValueError) as exc:
        return None, None, [], f"could not write the base tree at {tree}: {exc}"
    return tree, commit, listed, None


def _blob_id(algorithm: str, data: bytes) -> str:
    return hashlib.new(algorithm, b"blob %d\0" % len(data) + data).hexdigest()


def _write_tree(repo: Path, commit: str, tree: Path) -> list[Path]:
    """Make `tree` hold exactly the commit's files, read from git objects with no filter, attribute
    or hook: blobs as files (the executable bit kept), symlinks as symlinks, submodules as empty
    directories. A file whose bytes are already right is left alone, so it keeps its mtime.
    Returns the regular files, as repository_files would list them. Raises RuntimeError when two
    of the commit's names are one directory entry here (a case-insensitive or normalizing volume)."""
    form = _git(repo, "rev-parse", "--show-object-format")
    algorithm = form.stdout.strip() if form.returncode == 0 and form.stdout.strip() else "sha1"
    listing = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit)
    if listing.returncode != 0:
        raise RuntimeError(f"git ls-tree failed: {listing.stderr.strip()[:300]}")
    entries: dict[str, tuple[str, str]] = {}
    directories: set[str] = set()
    for record in listing.stdout.split("\0"):
        if not record:
            continue
        meta, _, name = record.partition("\t")
        mode, kind, sha = meta.split(" ")
        parts = name.split("/")
        if any(part in {"", ".", ".."} or part.lower() == ".git" for part in parts):
            raise RuntimeError(f"the base commit holds a path git refuses to check out: {name!r}")
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
        if kind == "commit":
            directories.add(name)  # A submodule: an empty directory, as a checkout without it leaves.
        elif kind == "blob":
            entries[name] = (mode, sha)
    # What the base does not have goes: earlier bases' files, build output, anything planted.
    for root, directory_names, file_names in os.walk(tree):
        here = Path(root)
        prefix = "" if here == tree else here.relative_to(tree).as_posix() + "/"
        for name in list(directory_names):
            relative, path = prefix + name, here / name
            if path.is_symlink():
                directory_names.remove(name)
                if entries.get(relative, ("",))[0] != "120000":
                    path.unlink()
            elif relative not in directories:
                directory_names.remove(name)
                shutil.rmtree(path)
        for name in file_names:
            if prefix + name not in entries:
                (here / name).unlink()
    # Directories first, so a blob that names one of them (on this filesystem) is caught below.
    for name in sorted(directories):
        (_real_parent(tree, name) / name.rsplit("/", 1)[-1]).mkdir(exist_ok=True)
    _one_entry_each(tree, sorted(directories))
    wanted = []
    for name, (mode, sha) in sorted(entries.items()):
        path = _real_parent(tree, name) / name.rsplit("/", 1)[-1]
        if mode == "120000":
            if path.is_symlink() and _blob_id(algorithm, os.fsencode(os.readlink(path))) == sha:
                continue
        elif path.is_file() and not path.is_symlink() and _blob_id(algorithm, path.read_bytes()) == sha:
            executable = mode == "100755"
            if bool(path.stat().st_mode & 0o100) != executable:
                path.chmod(0o755 if executable else 0o644)
            continue
        if path.is_dir() and not path.is_symlink():
            # Every directory left here is one the base has (the walk above removed the rest), so
            # this blob is that directory on this filesystem (case or Unicode normalization).
            other = next((directory for directory in sorted(directories)
                          if os.path.samefile(tree / directory, path)), name)
            raise RuntimeError(_collision(name, other))
        wanted.append((name, mode, sha))
    if wanted:
        _write_blobs(repo, tree, wanted)
    _one_entry_each(tree, sorted(entries))
    return sorted(tree / name for name, (mode, _) in entries.items()
                  if mode != "120000" and not any(part in IGNORED_DIRS for part in name.split("/")))


def _collision(name: str, other: str) -> str:
    return (f"the base commit holds both {other!r} and {name!r}, which name one directory entry on this "
            "filesystem (it folds case or normalizes Unicode), so the base tree cannot hold them both; "
            "audit from a clone on a case-sensitive volume")


def _one_entry_each(tree: Path, names: list[str]) -> None:
    """Refuse when two of the base's names landed on one directory entry (same device and inode)."""
    seen: dict[tuple[int, int], str] = {}
    for name in names:
        try:
            info = os.lstat(tree / name)
        except FileNotFoundError:
            continue
        other = seen.setdefault((info.st_dev, info.st_ino), name)
        if other != name:
            raise RuntimeError(_collision(name, other))


def _real_parent(tree: Path, name: str) -> Path:
    """The directory `name` goes in, created as needed; never through a symlink or over a file."""
    current = tree
    for part in name.split("/")[:-1]:
        current = current / part
        if not os.path.lexists(current):
            current.mkdir()
        elif current.is_symlink() or not current.is_dir():
            raise RuntimeError(f"{name!r} would be written through {current}, which is a symlink or a file")
    return current


def _write_blobs(repo: Path, tree: Path, wanted: list[tuple[str, str, str]]) -> None:
    prefix, environment = _no_execute_git(repo)
    process = subprocess.Popen([*prefix, "cat-file", "--batch"], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment)
    assert process.stdin is not None and process.stdout is not None
    try:
        for name, mode, sha in wanted:
            process.stdin.write(sha.encode() + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().split()
            if len(header) != 3 or header[1] != b"blob":
                raise RuntimeError(f"git has no blob {sha} for {name!r}")
            size = int(header[2])
            data = process.stdout.read(size)
            process.stdout.read(1)
            if len(data) != size:
                raise RuntimeError(f"git returned {len(data)} of {size} bytes for {name!r}")
            path = tree / name
            if mode == "120000":
                if os.path.lexists(path):
                    path.unlink()
                os.symlink(os.fsdecode(data), path)
                continue
            descriptor, temporary = tempfile.mkstemp(prefix=".hangover-", dir=path.parent)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                os.chmod(temporary, 0o755 if mode == "100755" else 0o644)
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
    finally:
        process.stdin.close()
        process.stdout.close()
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def _audit_view(result: dict[str, Any]) -> dict[str, Any]:
    """One side of an audit without its findings: what a review packet projects, log paths included."""
    view = {key: result.get(key) for key in ("status", "version", "tools", "policy_sha256", "sections", "warnings", "summary")}
    if result.get("refusal"):
        view["refusal"] = result["refusal"]
    view["raw_artifacts"] = {name: logs for name, command in (result.get("commands") or {}).items()
                             if (logs := {key: command[key] for key in ("stdout", "stderr") if command.get(key)})}
    return view
