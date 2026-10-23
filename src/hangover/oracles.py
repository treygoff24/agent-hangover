from __future__ import annotations

import functools
import json
import re
import os
import subprocess
import tempfile
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .model import digest, write_json
from .finding_identity import assign_complexity_identities
from .fallow_evidence import caveat_reasons, degrading_diagnostics, degrading_index, semantic_caveat
from .repository import (MAX_CAPTURE_BYTES, captured_text, diagnostic_text, git_safe_environment,
                         no_execute_git_active)
from .process import run_logged
from .packets import compact_review_issue
from .scope import select_scope

TOOL_ROOT = Path(__file__).resolve().parents[2]
FALLOW_VERSION = "3.31.0"
MAX_REVIEW_BYTES = 8 * 1024 * 1024
DELEGATE_TIMEOUT_GRACE = 15
SCHEMA_CAPABLE_LANES = {"codex", "claude"}
REVIEW_FINDING_FIELDS = {
    "category",
    "title",
    "evidence",
    "files",
    "symbols",
    "harm",
    "proposed_change",
    "invariants",
    "risk",
    "priority",
    "confidence",
    "verification",
    "chesterton",
}
REVIEW_CATEGORIES = {
    "abstraction",
    "architecture",
    "behavior_regression",
    "comments_docs",
    "compatibility",
    "complexity",
    "configuration",
    "dead_code",
    "defensive_code",
    "duplication",
    "indirection",
    "layering",
    "module_boundaries",
    "naming",
    "other",
    "readability",
    "state",
    "test_regression",
    "tests",
    "types",
    "validation",
}

DEAD_CODE_FIELDS = {
    "unused_files": ("Unused file", "P1", "medium", "medium"),
    "unused_exports": ("Unused export", "P1", "low", "high"),
    "unused_types": ("Unused type", "P2", "low", "high"),
    "unused_dependencies": ("Unused dependency", "P1", "medium", "medium"),
    "unused_dev_dependencies": ("Unused development dependency", "P2", "low", "medium"),
    "unused_optional_dependencies": ("Unused optional dependency", "P2", "medium", "medium"),
    "unused_enum_members": ("Unused enum member", "P2", "low", "high"),
    "unused_class_members": ("Unused class member", "P2", "medium", "medium"),
    "unresolved_imports": ("Unresolved import", "P0", "low", "high"),
    "unlisted_dependencies": ("Unlisted dependency", "P0", "low", "high"),
    "duplicate_exports": ("Duplicate export", "P1", "medium", "high"),
    "circular_dependencies": ("Dependency cycle", "P1", "medium", "high"),
    "re_export_cycles": ("Re-export cycle", "P1", "medium", "high"),
    "boundary_violations": ("Architecture boundary violation", "P1", "medium", "high"),
    "boundary_coverage_violations": (
        "Architecture boundary coverage gap",
        "P2",
        "medium",
        "high",
    ),
    "boundary_call_violations": ("Forbidden cross-boundary call", "P1", "medium", "high"),
    "policy_violations": ("Architecture policy violation", "P1", "medium", "high"),
    "stale_suppressions": ("Stale analyzer suppression", "P2", "low", "high"),
    "type_only_dependencies": ("Type-only runtime dependency", "P2", "low", "medium"),
    "test_only_dependencies": ("Test-only runtime dependency", "P2", "low", "medium"),
    "dev_dependencies_in_production": (
        "Development dependency used in production",
        "P1",
        "medium",
        "high",
    ),
    "unused_store_members": ("Unused store member", "P2", "medium", "medium"),
    "unprovided_injects": ("Unprovided injected dependency", "P1", "high", "high"),
    "unrendered_components": ("Unrendered component", "P2", "medium", "medium"),
    "unused_component_props": ("Unused component prop", "P2", "medium", "medium"),
    "unused_component_emits": ("Unused component event", "P2", "medium", "medium"),
    "unused_component_inputs": ("Unused component input", "P2", "medium", "medium"),
    "unused_component_outputs": ("Unused component output", "P2", "medium", "medium"),
    "unused_svelte_events": ("Unused Svelte event", "P2", "medium", "medium"),
    "unused_server_actions": ("Unused server action", "P2", "high", "medium"),
    "unused_load_data_keys": ("Unused load-data key", "P2", "medium", "medium"),
    "private_type_leaks": ("Private type leak", "P1", "high", "high"),
    "unused_catalog_entries": ("Unused catalog entry", "P2", "medium", "medium"),
    "empty_catalog_groups": ("Empty catalog group", "P2", "low", "high"),
    "unresolved_catalog_references": (
        "Unresolved catalog reference",
        "P0",
        "high",
        "high",
    ),
    "unused_dependency_overrides": ("Unused dependency override", "P2", "medium", "medium"),
    "misconfigured_dependency_overrides": (
        "Misconfigured dependency override",
        "P1",
        "high",
        "high",
    ),
    "invalid_client_exports": ("Invalid client export", "P1", "high", "high"),
    "mixed_client_server_barrels": (
        "Mixed client/server barrel",
        "P1",
        "high",
        "high",
    ),
    "misplaced_directives": ("Misplaced framework directive", "P1", "high", "high"),
    "route_collisions": ("Route collision", "P0", "high", "high"),
    "dynamic_segment_name_conflicts": (
        "Dynamic route segment conflict",
        "P0",
        "high",
        "high",
    ),
}

# Fallow 3.14.0 issue-registry.json maps structured result keys to resolved
# RulesConfig keys. Keep this explicit so rule policy is never inferred from
# spelling conventions.
DEAD_CODE_RULE_BY_FIELD = {
    "unused_files": "unused-files",
    "unused_exports": "unused-exports",
    "unused_types": "unused-types",
    "private_type_leaks": "private-type-leaks",
    "unused_dependencies": "unused-dependencies",
    "unused_dev_dependencies": "unused-dev-dependencies",
    "unused_optional_dependencies": "unused-optional-dependencies",
    "unused_enum_members": "unused-enum-members",
    "unused_class_members": "unused-class-members",
    "unused_store_members": "unused-store-members",
    "unresolved_imports": "unresolved-imports",
    "unlisted_dependencies": "unlisted-dependencies",
    "duplicate_exports": "duplicate-exports",
    "type_only_dependencies": "type-only-dependencies",
    "test_only_dependencies": "test-only-dependencies",
    "dev_dependencies_in_production": "dev-dependencies-in-production",
    "circular_dependencies": "circular-dependencies",
    "re_export_cycles": "re-export-cycle",
    "boundary_violations": "boundary-violation",
    "boundary_coverage_violations": "boundary-violation",
    "boundary_call_violations": "boundary-violation",
    "policy_violations": "policy-violation",
    "invalid_client_exports": "invalid-client-export",
    "mixed_client_server_barrels": "mixed-client-server-barrel",
    "misplaced_directives": "misplaced-directive",
    "unprovided_injects": "unprovided-injects",
    "unrendered_components": "unrendered-components",
    "unused_component_props": "unused-component-props",
    "unused_component_emits": "unused-component-emits",
    "unused_component_inputs": "unused-component-inputs",
    "unused_component_outputs": "unused-component-outputs",
    "unused_svelte_events": "unused-svelte-events",
    "unused_server_actions": "unused-server-actions",
    "unused_load_data_keys": "unused-load-data-keys",
    "route_collisions": "route-collision",
    "dynamic_segment_name_conflicts": "dynamic-segment-name-conflict",
    "stale_suppressions": "stale-suppressions",
    "unused_catalog_entries": "unused-catalog-entries",
    "empty_catalog_groups": "empty-catalog-groups",
    "unresolved_catalog_references": "unresolved-catalog-references",
    "unused_dependency_overrides": "unused-dependency-overrides",
    "misconfigured_dependency_overrides": "misconfigured-dependency-overrides",
    "prop_drilling_chains": "prop-drilling",
    "thin_wrappers": "thin-wrapper",
    "duplicate_prop_shapes": "duplicate-prop-shape",
}


def review_environment(names: list[str] | None = None) -> dict[str, str]:
    environment = git_safe_environment()
    for name in names or []:
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _runner_binary(
    name: str, variable: str, *, reject_shell_wrapper: bool = False
) -> Path | None:
    override = os.environ.get(variable)
    if override:
        candidate = Path(override).expanduser().resolve()
        return candidate if candidate.is_file() and os.access(candidate, os.X_OK) else None
    seen = set()
    for directory in os.environ.get("PATH", os.defpath).split(os.pathsep):
        candidate = (Path(directory).expanduser() / name).resolve()
        if candidate in seen or not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        seen.add(candidate)
        try:
            with candidate.open("rb") as handle:
                first_line = handle.readline(160).decode(errors="ignore").lower()
        except OSError:
            continue
        if reject_shell_wrapper and first_line.startswith("#!") and any(
            shell in first_line
            for shell in (
                "/bash",
                "/dash",
                "/fish",
                "/sh",
                "/zsh",
                "env bash",
                "env dash",
                "env fish",
                "env sh",
                "env zsh",
            )
        ):
            continue
        return candidate
    return None


def codex_binary() -> Path | None:
    return _runner_binary("codex", "HANGOVER_CODEX_BIN", reject_shell_wrapper=True)


def delegate_binary() -> Path | None:
    return _runner_binary("delegate", "HANGOVER_DELEGATE_BIN")


def _fallow_path() -> Path | None:
    override = os.environ.get("HANGOVER_FALLOW_BIN")
    if override:
        candidate = Path(override).expanduser().resolve()
        return candidate if candidate.is_file() else None
    bundled = TOOL_ROOT / "node_modules" / ".bin" / "fallow"
    if bundled.exists():
        return bundled.resolve()
    return None


def fallow_version() -> str | None:
    binary = _fallow_path()
    return _fallow_version_of(binary) if binary else None


@functools.lru_cache(maxsize=None)
def _fallow_version_of(binary: Path) -> str | None:
    """One version probe per binary for this CLI process, not per analyzer command."""
    try:
        result = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env=git_safe_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    output = result.stdout.strip() or result.stderr.strip()
    return output.splitlines()[0] if output else None


def _capture(
    command: list[str], cwd: Path, stdout_path: Path, stderr_path: Path,
    timeout: float, environment: dict[str, str], *, input_text: str | None = None,
    successful_codes: tuple[int, ...] = (0,),
    redact_names: Iterable[str] = (),
) -> dict[str, Any]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        capture = run_logged(command, cwd=cwd, env=environment, stdout_path=stdout_path,
                             stderr_path=stderr_path, timeout_seconds=timeout,
                             input_text=input_text, max_output_bytes=MAX_CAPTURE_BYTES)
        status = capture.status
        if status == "exited":
            status = "completed" if capture.exit_code in successful_codes else "failed"
        result = {"status": status, "exit_code": capture.exit_code,
                "duration_seconds": capture.duration_seconds, "stdout": str(stdout_path),
                "stderr": str(stderr_path), "stdout_tail": capture.stdout_tail[-1200:],
                "stderr_tail": (capture.stderr_tail or "")[-1200:],
                "capture_truncated": capture.truncated,
                "captured_stdout_bytes": capture.stdout_bytes, "captured_stderr_bytes": capture.stderr_bytes}
        if status != "completed":
            reason = diagnostic_text(capture.stdout_tail, capture.stderr_tail or "", redact_names)
            result["error"] = f"process {status} (exit {capture.exit_code}): {reason}"
        return result
    except OSError as exc:
        message = str(exc)
        with stderr_path.open("a") as handle:
            handle.write(message + "\n")
        return {"status": "failed", "exit_code": None, "duration_seconds": round(time.monotonic() - started, 3),
                "stdout": str(stdout_path), "stderr": str(stderr_path), "stdout_tail": "",
                "stderr_tail": message[-1200:], "error": message, "capture_truncated": False}


def _review_output(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise RuntimeError("refusing symlinked review output")
    value = json.loads(captured_text(path, MAX_REVIEW_BYTES))
    if not isinstance(value, dict):
        raise RuntimeError("review output must be a JSON object")
    return value


def _invalid_output(result: dict[str, Any], stderr_path: Path, error: Exception,
                    redact_names: Iterable[str] = ()) -> None:
    result["status"] = "unverifiable" if isinstance(error, UnverifiableReview) else "invalid_output"
    result["error"] = diagnostic_text("", str(error), redact_names)
    with stderr_path.open("a") as handle:
        handle.write(f"\n{result['error']}\n")


def _run_fallow(
    repo: Path, run_dir: Path, name: str, arguments: list[str], timeout: int = 600,
    *, clock_epoch: int | None = None,
) -> dict[str, Any]:
    if no_execute_git_active():
        # Static mode never runs Fallow (cli._analyzer_plan skips it): it reads tsconfig chains,
        # node_modules manifests and plugin files in ways no precheck follows exactly.
        raise RuntimeError("internal: Fallow must not run under --no-checks")
    binary = _fallow_path()
    if not binary:
        return {"status": "unavailable", "exit_code": None, "data": None}
    actual_version = fallow_version()
    if actual_version != f"fallow {FALLOW_VERSION}":
        raw_path = run_dir / "fallow" / f"{name}.json"
        stderr_path = run_dir / "fallow" / f"{name}.stderr"
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text("")
        message = (
            f"Expected fallow {FALLOW_VERSION}, got {actual_version or 'an unreadable version'}.\n"
        )
        stderr_path.write_text(message)
        return {
            "status": "version_mismatch",
            "exit_code": None,
            "duration_seconds": 0,
            "command": [str(binary), "--version"],
            "raw": str(raw_path),
            "stderr": str(stderr_path),
            "stderr_tail": message,
            "data": None,
        }
    command = [str(binary), "--root", str(repo), *arguments, "--format", "json", "--quiet"]
    raw_path = run_dir / "fallow" / f"{name}.json"
    stderr_path = run_dir / "fallow" / f"{name}.stderr"
    environment = {**git_safe_environment(), "npm_config_loglevel": "error"}
    environment.pop("FALLOW_CLOCK_EPOCH", None)
    if name == "health" and clock_epoch is not None:
        environment["FALLOW_CLOCK_EPOCH"] = str(clock_epoch)
    result = _capture(command, repo, raw_path, stderr_path, timeout,
                      environment, successful_codes=(0, 1))
    status = "error" if result["status"] == "failed" else result["status"]
    data: dict[str, Any] | None = None
    if status == "completed":
        try:
            parsed = json.loads(captured_text(raw_path))
            if isinstance(parsed, dict):
                data = parsed
            else:
                status = "invalid_json"
        except (OSError, ValueError, RuntimeError):
            status = "invalid_json"
    return {
        "status": status,
        "exit_code": result["exit_code"],
        "duration_seconds": result["duration_seconds"],
        "command": command,
        "raw": str(raw_path),
        "stderr": str(stderr_path),
        "stderr_tail": result["stderr_tail"],
        "capture_truncated": result["capture_truncated"],
        **({"error": result["error"]} if result.get("error") else {}),
        "data": data,
    }


def run_fallow_scan(
    repo: Path,
    run_dir: Path,
    inventory: dict[str, Any],
    *,
    dead_code_mode: str | None = None,
    clock_epoch: int | None = None,
) -> dict[str, Any]:
    if dead_code_mode not in {None, "syntactic", "type-aware"}:
        raise ValueError(f"unsupported dead-code analysis mode: {dead_code_mode!r}")
    if not (inventory.get("javascript") or inventory.get("typescript")):
        return {
            "status": "not_applicable",
            "version": fallow_version(),
            "dead_code_mode": "syntactic",
            "commands": {},
        }
    config = _normalize_fallow_result(
        _run_fallow(repo, run_dir, "config", ["config"])
    )
    dead_code_arguments = ["dead-code"]
    if dead_code_mode == "type-aware" or (
        dead_code_mode is None and inventory.get("typescript")
    ):
        dead_code_arguments.append("--type-aware")
    elif dead_code_mode == "syntactic":
        dead_code_arguments.append("--no-type-aware")
    dead_code = _normalize_fallow_result(
        _run_fallow(repo, run_dir, "dead-code", dead_code_arguments)
    )
    if "--type-aware" in dead_code_arguments and _fallow_command_failed(dead_code):
        type_aware_attempt = _retain_type_aware_fallow_artifacts(dead_code)
        dead_code = _normalize_fallow_result(
            _run_fallow(
                repo, run_dir, "dead-code", ["dead-code", "--no-type-aware"]
            )
        )
        dead_code["fallback"] = "type_aware_failed"
        dead_code["fallback_reason"] = _fallow_error_line(type_aware_attempt)
        dead_code["type_aware_attempt"] = type_aware_attempt
    commands = {
        "config": config,
        "dead_code": dead_code,
        "dupes": _normalize_fallow_result(
            _run_fallow(repo, run_dir, "dupes", ["dupes"])
        ),
        "health": _normalize_fallow_result(
            _run_fallow(
                repo,
                run_dir,
                "health",
                [
                    "health",
                    "--score",
                    "--complexity",
                    "--file-scores",
                    "--hotspots",
                    "--targets",
                    # Fallow 3.14.0's .fallow/churn.bin is keyed by absolute repo path and
                    # never expires commits that age out of the hotspot window: a moved
                    # repo reports zero hotspots (+10 score), a long-lived one reports
                    # phantom hotspots. The scan is evidence, so recompute churn every time.
                    "--no-cache",
                ],
                **({"clock_epoch": clock_epoch} if clock_epoch is not None else {}),
            )
        ),
        "flags": _normalize_fallow_result(
            # --retirement adds code-derived removal reasons; --flag-age off keeps
            # the evidence reproducible (ages grow with the wall clock).
            _run_fallow(repo, run_dir, "flags", ["flags", "--retirement", "--flag-age", "off"])
        ),
    }
    gaps = _fallow_finding_gaps(commands)
    for section, prefix in (("dead_code", "dead-code:"), ("dupes", "dupes:")):
        section_gaps = [gap for gap in gaps if gap.startswith(prefix)]
        if section_gaps and commands[section].get("status") == "completed":
            commands[section]["status"] = "inconsistent"
            commands[section]["error"] = "; ".join(section_gaps)
    statuses = {item["status"] for item in commands.values()}
    if "unavailable" in statuses:
        status = "unavailable"
    elif statuses <= {"completed"}:
        status = "completed"
    else:
        status = "partial"
    warnings = list(gaps)
    if dead_code.get("fallback") == "type_aware_failed":
        # The plain scan is complete evidence; the sidecar failure is a caveat, not a gap.
        warnings.append(
            "dead-code: type-aware sidecar failed "
            f"({dead_code.get('fallback_reason', 'unknown failure')}); "
            "findings come from the non-type-aware scan"
        )
    disabled_categories = disabled_fallow_categories(commands)
    disabled_findings = _disabled_fallow_finding_counts(commands)
    for rule, count in sorted(disabled_findings.items()):
        warnings.append(
            f"dead-code: Fallow reported {count} finding(s) for disabled rule "
            f"{rule}; excluded from hangover"
        )
    degraded: dict[str, int] = {}
    for item in degrading_diagnostics({"commands": commands}):
        degraded[item["kind"]] = degraded.get(item["kind"], 0) + 1
    if degraded:
        warnings.append(
            "analysis degraded: "
            + ", ".join(f"{count} {kind}" for kind, count in sorted(degraded.items()))
            + "; Fallow did not fully analyze these inputs (see workspace_diagnostics)"
        )
    function_inventory = _function_inventory(repo, run_dir, commands.get("health", {}))
    return {
        "status": status,
        "warnings": warnings,
        **({"function_inventory": function_inventory} if function_inventory else {}),
        "version": fallow_version(),
        "dead_code_mode": fallow_dead_code_mode(dead_code),
        "disabled_finding_categories": disabled_categories,
        "disabled_rule_findings": [
            {"rule": rule, "count": count}
            for rule, count in sorted(disabled_findings.items())
        ],
        "dependency_analysis": "complete" if inventory.get("has_node_modules") else "incomplete",
        "commands": commands,
        "summary": summarize_fallow(commands),
    }


def _function_inventory(repo: Path, run_dir: Path, health: dict[str, Any]) -> dict[str, Any] | None:
    """Every function Fallow sees, for the files and names that have complexity findings.

    A `health` run with every threshold at zero lists each function it parsed,
    syntax-aware, so it can prove a name is unique in its file where the
    threshold-limited findings cannot (a sibling below its threshold is absent
    there). Only complete evidence counts: the listing must equal Fallow's own
    functions-analyzed count. Missing or incomplete evidence returns None and
    complexity cards use the span identities. Stored compactly: positions for
    the reported (path, name) pairs only.
    """
    data = health.get("data") if isinstance(health, dict) else None
    reported = {(item.get("path"), item.get("name")) for item in (data or {}).get("findings") or []
                if isinstance(item, dict)}
    if not reported:
        return None
    result = _normalize_fallow_result(_run_fallow(
        repo, run_dir, "functions",
        ["health", "--complexity", "--max-cyclomatic", "0", "--max-cognitive", "0", "--max-crap", "0"]))
    payload = result.get("data")
    if result.get("status") != "completed" or not isinstance(payload, dict):
        return None
    findings = payload.get("findings")
    analyzed = (payload.get("summary") or {}).get("functions_analyzed")
    if (not isinstance(findings, list) or type(analyzed) is not int or analyzed != len(findings)
            or not all(isinstance(item, dict) for item in findings)):
        return None
    positions: dict[tuple[Any, Any], list[list[Any]]] = {}
    for item in findings:
        key = (item.get("path"), item.get("name"))
        if key in reported:
            positions.setdefault(key, []).append([item.get("line"), item.get("col")])
    return {"complete": True, "functions": [
        {"path": path, "name": name, "positions": sorted(places)} for (path, name), places in sorted(
            positions.items(), key=lambda entry: (str(entry[0][0]), str(entry[0][1])))]}


def _fallow_payload(result: dict[str, Any]) -> dict[str, Any] | None:
    data = result.get("data")
    if isinstance(data, dict):
        return data
    raw = result.get("raw")
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(Path(raw).read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def fallow_dead_code_mode(result: dict[str, Any]) -> str:
    explicit = result.get("dead_code_mode")
    if explicit in {"syntactic", "type-aware"}:
        return explicit
    summary = result.get("summary")
    if isinstance(summary, dict) and summary.get("dead_code_mode") in {
        "syntactic",
        "type-aware",
    }:
        return summary["dead_code_mode"]
    commands = result.get("commands")
    dead_code = (
        commands.get("dead_code", {}) if isinstance(commands, dict) else result
    )
    if dead_code.get("fallback") == "type_aware_failed":
        return "syntactic"
    payload = _fallow_payload(dead_code) or {}
    identity = payload.get("_meta", {}).get("type_aware", {}).get("identity", {})
    if isinstance(identity, dict) and identity.get("mode") == "type-aware":
        return "type-aware"
    # Legacy syntactic artifacts have no mode marker at all.
    return "syntactic"


def _resolved_fallow_rules(commands: dict[str, dict[str, Any]]) -> dict[str, str]:
    config = _fallow_payload(commands.get("config", {})) or {}
    rules = config.get("rules")
    if not isinstance(rules, dict):
        return {}
    return {key: value for key, value in rules.items() if isinstance(value, str)}


def disabled_fallow_categories(
    commands: dict[str, dict[str, Any]],
) -> dict[str, str]:
    rules = _resolved_fallow_rules(commands)
    return {
        field: rule
        for field, rule in DEAD_CODE_RULE_BY_FIELD.items()
        if rules.get(rule) == "off"
    }


def _reported_fallow_count(dead: dict[str, Any], field: str) -> int:
    values = dead.get(field)
    if isinstance(values, list):
        return len(values)
    summary = dead.get("summary")
    count = summary.get(field) if isinstance(summary, dict) else None
    return int(count) if isinstance(count, (int, float)) else 0


def _fallow_finding_gaps(commands: dict[str, dict[str, Any]]) -> list[str]:
    """A category count is not replacement evidence for its missing records.

    Compare only reported category counts, not total_issues: categories may
    overlap, and an aggregate cannot identify the missing work. Disabled rules
    are deliberate policy exclusions. Preserve the payload for inspection.
    """
    dead = _fallow_payload(commands.get("dead_code", {})) or {}
    summary = dead.get("summary", {})
    gaps = []
    if not isinstance(summary, dict):
        gaps.append("dead-code: invalid summary; finding completeness is unknown")
        summary = {}
    disabled = disabled_fallow_categories(commands)
    for field in DEAD_CODE_FIELDS.keys() - disabled.keys():
        if field not in summary:
            continue
        count = summary[field]
        records = dead.get(field, [])
        if field == "unused_dependencies":
            # Fallow's summary aggregates production, development, and optional dependencies.
            groups = [dead.get(key, []) for key in (
                "unused_dependencies", "unused_dev_dependencies", "unused_optional_dependencies")]
            if all(isinstance(group, list) for group in groups):
                records = [item for group in groups for item in group]
            else:
                records = None
        if (type(count) is not int or count < 0 or not isinstance(records, list)
                or any(not isinstance(item, dict) for item in records) or count != len(records)):
            gaps.append(f"dead-code: {field} summary does not match its finding records; evidence is incomplete")
    dupes = _fallow_payload(commands.get("dupes", {})) or {}
    for field in ("clone_groups", "clone_families"):
        if field + "_shown" not in dupes and field + "_omitted" not in dupes:
            continue
        shown, omitted = dupes.get(field + "_shown"), dupes.get(field + "_omitted")
        total = (dupes.get("stats") or {}).get(field)
        records = dupes.get(field)
        if (any(type(n) is not int or n < 0 for n in (shown, omitted, total))
                or shown + omitted != total or omitted != 0 or not isinstance(records, list)
                or len(records) != shown):
            gaps.append(f"dupes: {field} omitted or inconsistent finding records; evidence is incomplete")
    return sorted(gaps)


def _disabled_fallow_finding_counts(
    commands: dict[str, dict[str, Any]],
) -> dict[str, int]:
    dead = _fallow_payload(commands.get("dead_code", {})) or {}
    counts: dict[str, int] = {}
    for field, rule in disabled_fallow_categories(commands).items():
        count = _reported_fallow_count(dead, field)
        if count:
            counts[rule] = counts.get(rule, 0) + count
    return counts


def _normalize_fallow_result(result: dict[str, Any]) -> dict[str, Any]:
    payload = _fallow_payload(result)
    if payload is not None:
        result["data"] = payload
        if payload.get("error") is True and result.get("status") == "completed":
            result["status"] = "error"
    return result


def _fallow_command_failed(result: dict[str, Any]) -> bool:
    payload = _fallow_payload(result)
    if payload and payload.get("error") is True:
        return True
    return result.get("status") != "completed" and not (
        payload and isinstance(payload.get("summary"), dict)
    )


def _fallow_error_line(result: dict[str, Any]) -> str:
    payload = _fallow_payload(result) or {}
    message = payload.get("message") or result.get("error") or result.get("stderr_tail") or result.get("status")
    first_line = str(message or "unknown failure").strip().splitlines()[0]
    if payload.get("code"):
        first_line = f"{payload['code']}: {first_line}"
    if payload.get("help"):
        first_line += f"; {payload['help']}"
    return diagnostic_text(first_line, "")[:400]


def _retain_type_aware_fallow_artifacts(result: dict[str, Any]) -> dict[str, Any]:
    for field in ("raw", "stderr"):
        value = result.get(field)
        if not isinstance(value, str):
            continue
        source = Path(value)
        target = source.with_name(f"{source.stem}-type-aware{source.suffix}")
        if source.is_file():
            source.replace(target)
        result[field] = str(target)
    return result


def run_fallow_audit(repo: Path, run_dir: Path, base: str) -> dict[str, Any]:
    result = _normalize_fallow_result(
        _run_fallow(repo, run_dir, "audit", ["audit", "--base", base])
    )
    data = result.get("data") or {}
    if result["status"] == "completed" and data.get("verdict") not in ("pass", "warn", "fail"):
        result["status"] = "invalid_output"
        result["error"] = "Fallow audit did not return a supported verdict"
    return {
        "status": result["status"],
        "version": fallow_version(),
        "verdict": data.get("verdict"),
        "summary": data.get("summary", {}),
        "attribution": data.get("attribution", {}),
        "command": result,
    }


def summarize_fallow(commands: dict[str, dict[str, Any]]) -> dict[str, Any]:
    def successful_data(name: str) -> dict[str, Any]:
        data = commands.get(name, {}).get("data")
        return data if isinstance(data, dict) and data.get("error") is not True else {}

    dead = successful_data("dead_code")
    dupes = successful_data("dupes")
    health = successful_data("health")
    flags = successful_data("flags")
    config = successful_data("config")
    disabled_categories = disabled_fallow_categories(commands)
    dead_summary = dict(dead.get("summary", {}))
    disabled_count = 0
    for field in disabled_categories:
        disabled_count += _reported_fallow_count(dead, field)
        if field in dead_summary:
            dead_summary[field] = 0
    raw_total = dead.get("total_issues")
    if not isinstance(raw_total, (int, float)):
        raw_total = dead_summary.get("total_issues")
    filtered_total = (
        max(0, raw_total - disabled_count)
        if isinstance(raw_total, (int, float))
        else None
    )
    if filtered_total is not None:
        dead_summary["total_issues"] = filtered_total
    score = health.get("health_score") or {}
    health_summary = health.get("summary")
    return {
        "dead_code_mode": fallow_dead_code_mode(commands.get("dead_code", {})),
        "dead_code": dead_summary,
        "total_dead_code_issues": filtered_total,
        "duplication": dupes.get("stats", {}),
        "health_score": score.get("score"),
        "health_grade": score.get("grade"),
        "functions_above_threshold": (
            health_summary.get("functions_above_threshold")
            if isinstance(health_summary, dict)
            else None
        ),
        "vital_signs": health.get("vital_signs", {}),
        "feature_flags": flags.get("total_flags"),
        "resolved_config_sha256": digest(config),
    }


def extract_fallow_findings(result: dict[str, Any], repo: Path | None = None) -> list[dict[str, Any]]:
    commands = result.get("commands", {})
    dead = commands.get("dead_code", {}).get("data") or {}
    disabled_categories = disabled_fallow_categories(commands)
    caveat_index = degrading_index(result)
    findings: list[dict[str, Any]] = []
    unused_files = {
        item.get("path") for item in dead.get("unused_files", []) if isinstance(item, dict)
    }
    for field, (label, priority, risk, confidence) in DEAD_CODE_FIELDS.items():
        if field in disabled_categories:
            continue
        values = dead.get(field, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            item_paths = _item_paths(item)
            if field in {"unused_exports", "unused_types", "unused_class_members"} and any(
                path in unused_files for path in item_paths
            ):
                continue
            key = _finding_key(field, item)
            finding_id = _fallow_finding_id(item)
            subject = _subject(item, item_paths)
            dependency = "dependencies" in field
            suppression = next(
                (
                    {"config_key": action["config_key"], "value": action["value"]}
                    for action in item.get("actions", [])
                    if isinstance(action, dict)
                    and action.get("type") == "add-to-config"
                    and action.get("config_key")
                    and action.get("value")
                ),
                None,
            )
            evidence = f"Fallow {FALLOW_VERSION} reported {field}: {subject}."
            if dependency and result.get("dependency_analysis") == "incomplete":
                evidence += " node_modules is absent, so dependency evidence is incomplete."
            caveats = item.get("reachability_caveats") or []
            caveat_evidence = (["Reachability caveat: " + str(c) for c in caveats]
                              + semantic_caveat(item)
                              + caveat_reasons(result, item_paths, caveat_index))
            findings.append(
                {
                    # Fallow's stable id (3.31+) survives line moves and reformatting;
                    # without one (older output, id-less rules) the path+symbol key stays.
                    "fingerprint": ["fallow", field, "finding-id", finding_id] if finding_id else ["fallow", field, key],
                    **({"finding_id": finding_id, "legacy_fingerprint": ["fallow", field, key]} if finding_id else {}),
                    "source": "fallow",
                    "source_version": FALLOW_VERSION,
                    "category": field,
                    "title": f"{label}: {subject}",
                    **({"suppression": suppression} if suppression else {}),
                    "evidence": [evidence, *caveat_evidence],
                    "files": item_paths or ["package.json"],
                    "symbols": _item_symbols(item),
                    "harm": _harm(field),
                    "proposed_change": _proposed_change(field),
                    "invariants": [
                        "Runtime- and framework-discovered behavior remains available.",
                        "Public and serialization contracts remain compatible.",
                    ],
                    "risk": risk,
                    "priority": priority,
                    "confidence": "low"
                    if caveat_evidence or (dependency and result.get("dependency_analysis") == "incomplete")
                    else confidence,
                    "verification": [
                        "Trace all callers, dynamic registrations, framework conventions, and external consumers.",
                        "Run the repository's narrow affected tests, then its configured full gate.",
                    ],
                    "chesterton": "Static reachability is evidence, not proof; establish why the code exists before removal.",
                }
            )

    summary = dead.get("summary", {})
    unmapped = sorted(
        field
        for field, count in summary.items()
        if field not in DEAD_CODE_FIELDS
        and field not in disabled_categories
        and field != "total_issues"
        and isinstance(count, (int, float))
        and count > 0
    )
    if unmapped:
        related = sorted(
            {
                path
                for field in unmapped
                for item in dead.get(field, [])
                if isinstance(item, dict)
                for path in _item_paths(item)
            }
        )
        findings.append(
            {
                "fingerprint": ["fallow", "unmapped", unmapped],
                "source": "fallow",
                "source_version": FALLOW_VERSION,
                "category": "fallow_unmapped",
                "title": f"Inspect unnormalized Fallow categories: {', '.join(unmapped)}",
                "evidence": [
                    "Fallow reported nonzero categories that this hangover version does not normalize; inspect the raw dead-code JSON instead of discarding them."
                ],
                "files": related or ["package.json"],
                "symbols": [],
                "harm": "Silently dropping analyzer categories makes the persisted backlog incomplete.",
                "proposed_change": "Inspect the raw findings and update hangover's explicit mapping before remediating them.",
                "invariants": ["No analyzer finding is hidden to improve apparent health."],
                "risk": "medium",
                "priority": "P1",
                "confidence": "high",
                "verification": ["Map the category against Fallow's current structured output and rescan."],
                "chesterton": "Unknown analyzer categories require interpretation, not automated code deletion.",
            }
        )

    dupes = commands.get("dupes", {}).get("data") or {}
    for group in dupes.get("clone_groups", []) if isinstance(dupes.get("clone_groups"), list) else []:
        if not isinstance(group, dict):
            continue
        instances = group.get("instances", [])
        if not isinstance(instances, list):
            continue
        files = sorted(
            {item.get("file") for item in instances if isinstance(item, dict) and item.get("file")}
        )
        if not files:
            continue
        fingerprint = group.get("fingerprint") or json.dumps(files)
        clone_key = f"{fingerprint}:{len(instances)}"
        suppression = ({"config_key": "duplicates.ignoredClones", "value": clone_key}
                       if re.fullmatch(r"dup:(?:[0-9a-f]{8}|[0-9a-f]{16}(?:-r?[1-9][0-9]*)?):(?:[2-9]|[1-9][0-9]+)", clone_key)
                       else None)
        suggested_name = group.get("suggested_name")
        symbols = [str(suggested_name)] if suggested_name else []
        evidence = [
            f"Fallow found {group.get('line_count', '?')} duplicated lines "
            f"({group.get('token_count', '?')} tokens) across {len(instances)} instances in: "
            f"{', '.join(files)}."
        ]
        for instance in instances:
            if not isinstance(instance, dict) or not instance.get("file"):
                continue
            location = str(instance["file"])
            if instance.get("start_line") is not None:
                location += f":{instance['start_line']}-{instance.get('end_line', instance['start_line'])}"
            evidence.append(f"Instance: {location}")
            fragment = instance.get("fragment")
            if isinstance(fragment, str) and fragment.strip():
                excerpt = "\n".join(fragment.strip().splitlines()[:3])
                evidence.append(f"Fragment at {location}:\n{excerpt}")
        if suggested_name:
            evidence.append(f"Fallow suggests extracting `{suggested_name}`.")
        elif "spread" in group:
            evidence.append(f"Fallow clone spread: {group['spread']} "
                            "(maximum directory-tree or same-file line distance between instances).")
        findings.append(
            {
                "fingerprint": ["fallow", "duplication", fingerprint],
                "source": "fallow",
                "source_version": FALLOW_VERSION,
                "category": "duplication",
                **({"suppression": suppression} if suppression else {}),
                "duplication_identity": {"spans": [
                    {key: item.get(key) for key in ("file", "start_line", "end_line")}
                    for item in instances if isinstance(item, dict)
                ]},
                "title": _duplication_title(group.get("line_count", "?"), files, len(instances)),
                "evidence": evidence,
                "files": files,
                "symbols": symbols,
                "harm": "Repeated behavior can drift and forces maintainers to hold multiple implementations in mind.",
                "proposed_change": "First confirm the semantics are genuinely the same, then reuse the smallest existing primitive or consolidate once.",
                "invariants": ["All callers retain their current inputs, outputs, and side effects."],
                "risk": "medium",
                "priority": "P2",
                "confidence": "medium",
                "verification": ["Run behavior-focused tests for every affected caller."],
                "chesterton": "Similar text can encode deliberately different policy; establish shared semantics before extracting.",
            }
        )

    findings.extend(_feature_flag_findings(commands.get("flags", {}).get("data") or {}))

    findings.extend(_complexity_findings(commands.get("health", {}).get("data") or {}, repo,
                                         result.get("function_inventory")))
    return findings


# Retirement reasons that are code facts about the flag itself. The rest
# (one read site, test-only reads) say only that a flag is cheap to remove.
# hangover never passes --flag-state, so vendor-derived reasons cannot occur.
STRONG_RETIREMENT_REASONS = frozenset({
    "literal-constant", "identical-branches", "empty-branch", "guards-dead-code",
    "defined-never-read",
})


def _feature_flag_findings(flags: dict[str, Any]) -> list[dict[str, Any]]:
    """One card per flag name: Fallow's inventory plus its 3.30 retirement report.

    Retirement-only rows (for example a literal `const FEATURE_X = true`) are
    not in the inventory, so their sites come from the report.
    """
    sites: dict[str, list[dict[str, Any]]] = {}
    raw_flags = flags.get("feature_flags", [])
    for item in raw_flags if isinstance(raw_flags, list) else []:
        if isinstance(item, dict) and item.get("path"):
            sites.setdefault(str(item.get("flag_name", "unnamed flag")), []).append(item)
    inventoried = set(sites)
    retirement: dict[str, dict[str, Any]] = {}
    report = flags.get("retirement")
    rows = report.get("flags") if isinstance(report, dict) else None
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("flag_name"), str):
            continue
        # Fallow keys a flag by name and workspace; hangover keeps one card per
        # name, so every row's sites belong on it.
        name = row["flag_name"]
        reasons = [reason for reason in row.get("reasons") or [] if isinstance(reason, str)]
        entry = retirement.setdefault(name, {"reasons": [], "rows": []})
        entry["reasons"] += [r for r in reasons if r not in entry["reasons"]]
        entry["rows"].append(row)
        known = {(str(item["path"]), item.get("line")) for item in sites.get(name, [])}
        for site in row.get("sites") or []:
            if (isinstance(site, dict) and site.get("path")
                    and (str(site["path"]), site.get("line")) not in known):
                sites.setdefault(name, []).append(site)
                known.add((str(site["path"]), site.get("line")))
    for name in [name for name in sites if name not in inventoried and not retirement.get(name, {}).get("reasons")]:
        del sites[name]
    findings = []
    for name in sorted(sites):
        occurrences = sorted(sites[name], key=lambda item: (str(item["path"]), str(item.get("line", "?"))))
        if not occurrences:
            continue
        files = sorted({str(item["path"]) for item in occurrences})
        reasons = retirement.get(name, {}).get("reasons", [])
        rows = retirement.get(name, {}).get("rows", [])
        # Strong only when every row (every workspace) is settled by a code fact.
        strong = bool(rows) and all(
            any(reason in STRONG_RETIREMENT_REASONS for reason in row.get("reasons") or [])
            for row in rows)
        evidence = [
            (f"Fallow inventoried {name} at {item['path']}:{item.get('line', '?')}; this does not prove staleness."
             if "flag_name" in item else
             f"Fallow's retirement report found {name} at {item['path']}:{item.get('line', '?')}.")
            for item in occurrences
        ]
        if reasons:
            evidence.append(
                f"Fallow {FALLOW_VERSION} lists {name} as a retirement candidate: {', '.join(reasons)}. "
                "The reasons come from the code only, not from production flag state."
            )
            for row in retirement[name]["rows"]:
                for item in row.get("evidence") or []:
                    if isinstance(item, dict) and item.get("detail"):
                        evidence.append(f"{item.get('reason', '?')} at {item.get('path', '?')}:"
                                        f"{item.get('line', '?')}: {item['detail']}")
        findings.append(
            {
                "fingerprint": ["fallow", "feature_flag", name],
                "source": "fallow",
                "source_version": FALLOW_VERSION,
                "category": "feature_flag",
                "title": (f"Retire feature flag {name}" if strong
                          else f"Establish whether feature flag {name} still varies"),
                "evidence": evidence,
                "files": files,
                "symbols": [name],
                "harm": "A permanently settled branch retains two concepts and doubles reasoning paths.",
                "proposed_change": (
                    "Keep the behavior the code already selects, delete the flag read and the branch it can never take, and remove the flag definition."
                    if strong else
                    "Confirm production values and rollout ownership; remove the losing branch only if the flag no longer varies."
                ),
                "invariants": ["Current production behavior remains the selected behavior."],
                "risk": "medium" if strong else "high",
                "priority": "P2" if strong else "P3",
                "confidence": "medium" if strong else "low",
                "verification": ["Check runtime configuration and deployment history before changing code."],
                "chesterton": (
                    "Code shows the flag cannot vary as written; confirm no deployment overrides it (environment, remote config) before removal."
                    if strong else
                    "Inventory is not stale-proof; keep the flag unless runtime evidence establishes that it is settled."
                ),
            }
        )
    return findings


_FINDING_ID = re.compile(r"dslp-[0-9a-f]{10}")


def _introduced_finding_dispositions(
    issue: dict[str, Any] | None, snapshot: dict[str, Any]
) -> list[dict[str, Any]]:
    """Every finding an earlier verify of this remediation reported as introduced,
    with whether the current scan still reports it, so the reviewer sees the
    disposition instead of only the failure record in the issue history."""
    if not issue:
        return []
    seen = set(snapshot.get("finding_ids_seen", []))
    introduced: dict[str, str] = {}
    for event in issue.get("history", []):
        if event.get("event") != "verification_failed":
            continue
        for reason in event.get("reasons", []):
            if "introduced" not in reason:
                continue
            for finding_id in _FINDING_ID.findall(reason):
                introduced.setdefault(finding_id, event.get("run", ""))
    return [
        {
            "id": finding_id,
            "first_reported_in": run,
            "present_in_this_scan": finding_id in seen,
        }
        for finding_id, run in introduced.items()
    ]


def _rust_review_evidence(result: dict[str, Any]) -> dict[str, Any]:
    """Bounded analyzer evidence, never campaign history or prior model verdicts."""
    projection = {key: result[key] for key in (
        "status", "version", "tools", "policy_sha256", "sections", "warnings", "summary",
        "verdict", "introduced", "error",
    ) if key in result}
    artifacts = dict(result.get("raw_artifacts") or {})
    for name, command in result.get("commands", {}).items():
        logs = {key: command[key] for key in ("stdout", "stderr") if command.get(key)}
        if logs:
            artifacts[name] = logs
    projection["raw_artifacts"] = artifacts
    for side in ("current", "base"):
        if isinstance(result.get(side), dict):
            projection[side] = _rust_review_evidence(result[side])
    return projection


def prepare_review_packet(
    repo: Path,
    run_dir: Path,
    mode: str,
    snapshot: dict[str, Any],
    issue: dict[str, Any] | None = None,
    before_patch: Path | None = None,
    after_patch: Path | None = None,
    verification_token: str | None = None,
    review_scope: dict[str, Any] | None = None,
) -> Path:
    selected_scope = (review_scope or select_scope(repo)) if mode == "initial" else None
    context = run_dir / "review-context.json"
    write_json(context, {"snapshot": snapshot, "issue": issue, "review_scope": selected_scope})
    schema = run_dir / "review-schema.json"
    write_json(schema, json.loads((TOOL_ROOT / "schemas/review.schema.json").read_text()))
    compact_issue, remediation = compact_review_issue(issue)
    packet = {
        "schema_version": 2,
        "mode": mode,
        "verification_token": verification_token,
        "review_schema": str(schema),
        "change": {"base": snapshot.get("base"), "requested_base": snapshot.get("requested_base"),
                   "files": snapshot.get("changed_files", []), "full_gate": snapshot.get("full", False),
                   "check_selection": snapshot.get("check_selection")} if mode == "prevention" else None,
        "repo": str(repo),
        "instructions": snapshot.get("inventory", {}).get("instructions", []),
        "docs": snapshot.get("inventory", {}).get("docs", [])[:30],
        "inventory": snapshot.get("inventory", {}),
        "git": snapshot.get("git", {}),
        "native_checks": snapshot.get("checks", []),
        "check_comparison": snapshot.get("check_comparison", []),
        "fallow": {
            "status": snapshot.get("fallow", {}).get("status"),
            "version": snapshot.get("fallow", {}).get("version"),
            "dependency_analysis": snapshot.get("fallow", {}).get("dependency_analysis"),
            "summary": snapshot.get("fallow", {}).get("summary", {}),
            "raw_artifacts": {
                key: value.get("raw")
                for key, value in snapshot.get("fallow", {}).get("commands", {}).items()
                if value.get("raw")
            },
        },
        "fallow_comparison": snapshot.get("fallow_comparison"),
        "rust": _rust_review_evidence(snapshot["rust"]) if snapshot.get("rust") else None,
        "rust_comparison": snapshot.get("rust_comparison"),
        "issue": compact_issue,
        "remediation": remediation,
        "review_scope": {
            "kind": selected_scope["kind"], "requested": selected_scope["requested"],
            "files": selected_scope["files"] if selected_scope["kind"] == "selected" else None,
            "selected_count": len(selected_scope["files"]),
            "unselected_count": len(selected_scope["unselected_files"]),
            "finding_limit": selected_scope["finding_limit"],
        } if selected_scope else None,
        "implementer_notes": list(issue.get("fix_notes", [])) if issue else [],
        "introduced_findings": _introduced_finding_dispositions(issue, snapshot),
        "before_patch": str(before_patch) if before_patch else None,
        "after_patch": str(after_patch) if after_patch else None,
    }
    if audit_raw := snapshot.get("fallow", {}).get("command", {}).get("raw"):
        packet["fallow"]["raw_artifacts"]["audit"] = audit_raw
    packet["evidence"] = {
        "packet_bytes": 0,
        "contracts_complete": True,
        "retained_context": str(context),
        "retained_context_purpose": "Audit record, not a review input: includes prior history and verdicts.",
        "raw_artifacts_inlined": False,
        "limitation": "Native summaries and captured tails are included; raw logs are separate private artifacts. Report any missing evidence needed to judge the change.",
    }
    # Include this field's own digits in the size of write_json's serialization.
    while True:
        size = len((json.dumps(packet, indent=2) + "\n").encode())
        if packet["evidence"]["packet_bytes"] == size:
            break
        packet["evidence"]["packet_bytes"] = size
    packet_path = run_dir / "review-packet.json"
    write_json(packet_path, packet)
    prompt_name = {"initial": "initial-review.md", "prevention": "prevention-review.md"}.get(mode, "post-fix-review.md")
    prompt = (TOOL_ROOT / "prompts" / prompt_name).read_text()
    (run_dir / "review-prompt.md").write_text(
        prompt + f"\n\nReview packet: {packet_path}\nReview schema: {schema}\n"
    )
    return packet_path


def delegate_review_command(
    prompt_path: Path,
    schema_path: Path | None = None,
    timeout: int = 1200,
    *,
    lane: str = "codex",
    model: str | None = None,
    reasoning_effort: str | None = None,
) -> list[str]:
    if not isinstance(lane, str) or not lane:
        raise RuntimeError("review.delegate.lane must be a non-empty string")
    if model is not None and not isinstance(model, str):
        raise RuntimeError("review.delegate.model must be a string or null")
    if reasoning_effort is not None and not isinstance(reasoning_effort, str):
        raise RuntimeError("review.delegate.reasoning_effort must be a string or null")
    binary = delegate_binary()
    if not binary:
        raise RuntimeError(
            "no delegate binary found; set HANGOVER_DELEGATE_BIN or use `hangover review --prepare`"
        )
    command = [str(binary), "--json", lane, "safe"]
    if model:
        command.extend(["--model", model])
    if reasoning_effort:
        command.extend(["--reasoning-effort", reasoning_effort])
    if lane in SCHEMA_CAPABLE_LANES and schema_path:
        command.extend(["--output-schema", str(schema_path)])
    command.extend(["--prompt-file", str(prompt_path), "--timeout", str(timeout)])
    return command


def substitute_command_template(
    template: list[str],
    repo: Path,
    prompt_path: Path,
    output_path: Path,
    schema_path: Path,
) -> list[str]:
    if not isinstance(template, list) or not template or not all(
        isinstance(value, str) for value in template
    ):
        raise RuntimeError("review.command must be a non-empty array of strings")
    substitutions = {
        "{prompt}": str(prompt_path),
        "{output}": str(output_path),
        "{repo}": str(repo),
        "{schema}": str(schema_path),
    }
    return [substitutions.get(value, value) for value in template]


def _fenced(text: str) -> str:
    return text if text.endswith("\n") else text + "\n"


def _without_packet_pointer(prompt_text: str, packet_path: Path) -> str:
    pointers = {f"Review packet: {packet_path}", f"Review schema: {packet_path.parent / 'review-schema.json'}"}
    return "\n".join(
        line for line in prompt_text.splitlines() if line.strip() not in pointers
    )


def _delegate_prompt(
    prompt_text: str,
    schema_path: Path,
    packet_path: Path | None = None,
    *,
    include_schema: bool = True,
) -> str:
    if packet_path is not None:
        prompt_text = _without_packet_pointer(prompt_text, packet_path)
    sections = [prompt_text.rstrip()]
    if packet_path is not None:
        try:
            packet_text = captured_text(packet_path, MAX_REVIEW_BYTES)
            packet = json.loads(packet_text)
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"review packet unavailable or invalid: {packet_path}") from exc
        if not isinstance(packet, dict):
            raise RuntimeError("review packet must be a JSON object")
        sections.extend(
            [
                "\n\n## Review packet (inline JSON)\n",
                "The packet is reproduced below. Absolute artifact paths are not readable from this context; patches are inlined below. Repository-relative source paths may be inspected with the read tools supplied by your isolated workspace. Do not reach into the original checkout or the audit-only retained context. If the workspace or supplied evidence omits a needed file, report that gap rather than assuming its contents.\n",
                "```json\n",
                _fenced(packet_text),
                "```\n",
            ]
        )
        for field, label in (("before_patch", "Before patch"), ("after_patch", "After patch")):
            patch_path = packet.get(field)
            if not isinstance(patch_path, str) or not patch_path:
                continue
            try:
                patch_text = captured_text(Path(patch_path), MAX_REVIEW_BYTES)
            except OSError as exc:
                raise RuntimeError(f"review patch unavailable: {patch_path}") from exc
            sections.extend(
                [f"\n## {label} (inline diff)\n```diff\n", _fenced(patch_text), "```\n"]
            )
    if include_schema:
        schema = schema_path.read_text().strip()
        sections.extend(
            [
                "\n\n## Output contract\n",
                "Return exactly one raw JSON object matching the schema below. Do not use Markdown fences, commentary, or a completion report.\n",
                "Schema:\n",
                schema,
                "\n",
            ]
        )
    text = "".join(sections)
    if len(text.encode()) > MAX_REVIEW_BYTES:
        raise RuntimeError("inline review inputs exceed 8 MiB; select a smaller coherent change or use a reviewer with local artifact access")
    return text


def parse_delegate_review(assistant_text: str, mode: str) -> dict[str, Any]:
    if not isinstance(assistant_text, str):
        raise RuntimeError("delegate output did not contain assistant text")
    if len(assistant_text.encode("utf-8")) > MAX_REVIEW_BYTES:
        raise RuntimeError(f"review output exceeds the {MAX_REVIEW_BYTES}-byte parsing limit")
    decoder = json.JSONDecoder()
    review: dict[str, Any] | None = None
    cursor = 0
    while cursor < len(assistant_text):
        if assistant_text[cursor] not in "[{":
            cursor += 1
            continue
        try:
            candidate, end = decoder.raw_decode(assistant_text, cursor)
        except json.JSONDecodeError as exc:
            if exc.pos >= len(assistant_text) or exc.msg.startswith("Unterminated string"):
                raise RuntimeError(
                    "delegate output ends inside an unfinished JSON value; "
                    "the review is truncated, not clean"
                ) from exc
            cursor += 1
            continue
        if assistant_text[cursor] == "{" and isinstance(candidate, dict):
            review = candidate
        cursor = end
    if review is None:
        raise RuntimeError("delegate output did not contain a valid review JSON object")
    _validate_review(review, mode)
    return review


def _review_result(
    capture: dict[str, Any],
    packet_path: Path,
    output_path: Path,
    review: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        **capture,
        "packet": str(packet_path),
        "output": str(output_path),
        "review": review,
    }


class UnverifiableReview(RuntimeError):
    """A valid-shaped verdict that supplies no completed review evidence."""


def runner_environment_failure(text: str) -> str | None:
    """Recognize sandbox startup failures without echoing credential paths/logs."""
    codex_home = os.environ.get("CODEX_HOME", "").casefold()
    echoed = False
    model_output = False
    for line in text.splitlines():
        line = line.strip().casefold()
        if line in {"user", "codex", "assistant"}:
            echoed = True
            model_output = line != "user"
            continue
        if line.startswith(("hook:", "mcp:", "tokens used")):
            model_output = False
        if model_output:
            continue
        # Diagnostics are prefixed by Codex or bwrap. Bare startup denials
        # are accepted only before Codex begins echoing its conversation.
        diagnostic = line.startswith(("warning:", "error:", "bwrap:"))
        if not diagnostic and (echoed or not line.startswith("permission denied")):
            continue
        # Codex continues past failing to create its PATH aliases; that warning is not a startup failure.
        if "proceeding, even though" in line:
            continue
        if ((line.startswith("bwrap:") and ("permission denied" in line or "uid map" in line))
                or (line.startswith("warning:") and "codex's linux sandbox uses bubblewrap" in line
                    and "user namespaces" in line)
                or ("permission denied" in line and (".codex" in line or (codex_home and codex_home in line)))):
            return (
                "runner environment failure: Codex cannot start its sandbox or write its runtime files; "
                "use --runner delegate --lane claude, or run outside the confining sandbox "
                "(host write policies and container sandboxes can block bwrap)"
            )
    return None


def run_delegate_review(
    repo: Path,
    run_dir: Path,
    packet_path: Path,
    mode: str,
    timeout: int = 1200,
    *,
    lane: str = "codex",
    model: str | None = None,
    reasoning_effort: str | None = None,
    env: list[str] | None = None,
    prompt_path: Path | None = None,
    prompt_text: str | None = None,
    output_path: Path | None = None,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    run_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = prompt_path or run_dir / "review-prompt.md"
    output_path = output_path or run_dir / "review.json"
    schema_path = schema_path or TOOL_ROOT / "schemas" / "review.schema.json"
    prompt_text = prompt_text if prompt_text is not None else prompt_path.read_text()
    prompt_path = run_dir / "delegate-review-prompt.md"
    passes_schema_flag = lane in SCHEMA_CAPABLE_LANES and schema_path is not None
    prompt_path.write_text(
        _delegate_prompt(
            prompt_text,
            schema_path,
            packet_path,
            include_schema=not passes_schema_flag,
        )
    )
    transport_schema = schema_path
    if lane == "claude":
        # Claude's schema validator does not load the draft 2020-12 metaschema.
        # Keep the canonical schema intact and drop only the transport dialect.
        schema = json.loads(schema_path.read_text())
        schema.pop("$schema", None)
        transport_schema = run_dir / "delegate-review.schema.json"
        write_json(transport_schema, schema)
    command = delegate_review_command(
        prompt_path,
        transport_schema,
        timeout,
        lane=lane,
        model=model,
        reasoning_effort=reasoning_effort,
    )
    stdout_path = run_dir / "review.stdout"
    stderr_path = run_dir / "review.stderr"
    result = _capture(command, repo, stdout_path, stderr_path, timeout + DELEGATE_TIMEOUT_GRACE,
                      review_environment(env), redact_names=env or [])
    review: dict[str, Any] | None = None
    if result["status"] == "completed":
        try:
            envelope = json.loads(captured_text(stdout_path))
            if not isinstance(envelope, dict):
                raise RuntimeError("delegate output envelope must be a JSON object")
            child_exit_code = envelope.get("exitCode")
            if not isinstance(child_exit_code, int) or isinstance(child_exit_code, bool):
                raise RuntimeError("delegate output envelope has no integer exitCode")
            result["exit_code"] = child_exit_code
            result["reported_route"] = {
                "engine": envelope.get("engine"),
                "model": envelope.get("modelResolved"),
                "reasoning_effort": envelope.get("resolvedReasoningEffort"),
            }
            if any(value is not None and not isinstance(value, str) for value in result["reported_route"].values()):
                raise RuntimeError("Delegate returned invalid route metadata")
            if child_exit_code != 0 or envelope.get("assistantTextTruncated") is True:
                result["status"] = "failed"
                result["error"] = "Delegate child failed or its assistant text was truncated"
            else:
                review = parse_delegate_review(envelope.get("assistantText"), mode)
                write_json(output_path, review)
        except (OSError, ValueError, RuntimeError) as exc:
            review = None
            _invalid_output(result, stderr_path, exc, env or [])
    return _review_result(result, packet_path, output_path, review)


def run_command_review(
    repo: Path,
    run_dir: Path,
    packet_path: Path,
    mode: str,
    command_template: list[str],
    timeout: int = 1200,
    *,
    prompt_path: Path | None = None,
    prompt_text: str | None = None,
    output_path: Path | None = None,
    schema_path: Path | None = None,
    env: list[str] | None = None,
) -> dict[str, Any]:
    run_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = prompt_path or run_dir / "review-prompt.md"
    output_path = output_path or run_dir / "review.json"
    schema_path = schema_path or TOOL_ROOT / "schemas" / "review.schema.json"
    prompt_text = prompt_text if prompt_text is not None else prompt_path.read_text()
    command = substitute_command_template(
        command_template, repo, prompt_path, output_path, schema_path
    )
    uses_output = any(value == "{output}" for value in command_template)
    uses_prompt = any(value == "{prompt}" for value in command_template)
    stdout_path = run_dir / "review.stdout"
    stderr_path = run_dir / "review.stderr"
    result = _capture(command, repo, stdout_path, stderr_path, timeout, review_environment(env),
                      input_text=None if uses_prompt else prompt_text, redact_names=env or [])
    review: dict[str, Any] | None = None
    if result["status"] == "completed":
        try:
            if uses_output:
                review = _review_output(output_path)
            else:
                review = _review_output(stdout_path)
                write_json(output_path, review)
            _validate_review(review, mode)
        except (OSError, ValueError, RuntimeError) as exc:
            review = None
            _invalid_output(result, stderr_path, exc, env or [])
    return _review_result(result, packet_path, output_path, review)


def run_codex_review(
    repo: Path, run_dir: Path, packet_path: Path, mode: str, timeout: int = 1200,
    *, prompt_path: Path | None = None,
) -> dict[str, Any]:
    output_path = run_dir / "review.json"
    stdout_path = run_dir / "review.stdout"
    stderr_path = run_dir / "review.stderr"
    review_home = run_dir / "review-home"
    review_home.mkdir(mode=0o700)
    prompt = (prompt_path or run_dir / "review-prompt.md").read_text()
    # A run directory inside the target inherits its ancestor AGENTS.md. Keep
    # Codex outside that tree as well as disabling automatic project docs.
    with tempfile.TemporaryDirectory(prefix="hangover-review-") as directory:
        workspace = Path(directory).resolve()
        if workspace.is_relative_to(repo.resolve()):
            raise RuntimeError("review temporary workspace must be outside the target repository; choose an external TMPDIR")
        command = codex_review_command(repo, output_path, review_home, workspace=workspace)
        result = _capture(command, workspace, stdout_path, stderr_path, timeout, git_safe_environment(), input_text=prompt)
    review: dict[str, Any] | None = None
    stderr_text = stderr_path.read_text(errors="replace") if stderr_path.is_file() else ""
    # The runner echoes our supplied prompt; its contents are evidence, never
    # Codex diagnostics. The model's output is excluded by the line parser.
    environment_error = runner_environment_failure(stderr_text.replace(prompt, "", 1))
    if result["status"] == "completed":
        try:
            review = _review_output(output_path)
            _validate_review(review, mode)
        except (OSError, ValueError, RuntimeError) as exc:
            review = None
            _invalid_output(result, stderr_path, exc)
    if review is None and environment_error:
        result.update(status="environment_failure", error=environment_error)
    # Read only Codex's startup header, never echoed user/repository/model text.
    header = re.search(r"^OpenAI Codex v[^\n]*\n--------\n(.*?)\n--------(?:\n|$)", stderr_text, re.DOTALL | re.MULTILINE)
    metadata: dict[str, str | None] = {"model": None, "reasoning_effort": None}
    if header:
        for field, label in (("model", "model"), ("reasoning_effort", "reasoning effort")):
            match = re.search(rf"(?m)^{label}: ([^\n]+)$", header[1])
            if match:
                metadata[field] = match[1].strip() or None
    return {**_review_result(result, packet_path, output_path, review), **metadata}


def codex_review_command(
    repo: Path, output_path: Path, review_home: Path | None = None, *, workspace: Path
) -> list[str]:
    binary = codex_binary()
    if not binary:
        raise RuntimeError(
            "no direct Codex binary found; set HANGOVER_CODEX_BIN or use `hangover review --prepare`"
        )
    review_home = review_home or output_path.parent / "review-home"
    command = [
        str(binary),
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "-c",
        "project_doc_max_bytes=0",
        "-c",
        "shell_environment_policy.inherit=none",
        "-c",
        f"shell_environment_policy.set.HOME={json.dumps(str(review_home))}",
        "-c",
        f"shell_environment_policy.set.ZDOTDIR={json.dumps(str(review_home))}",
        "-c",
        'shell_environment_policy.set.SHELL="/bin/sh"',
        "-s",
        "read-only",
        "--add-dir",
        str(repo),
        "--output-schema",
        str((TOOL_ROOT / "schemas" / "review.schema.json").resolve()),
        "-o",
        str(output_path.resolve()),
        "-C",
        str(workspace),
        "--skip-git-repo-check",
    ]
    command.append("-")
    return command


def import_review(path: Path, mode: str) -> dict[str, Any]:
    try:
        review = _review_output(path)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"review output unavailable or invalid: {path}") from exc
    _validate_review(review, mode)
    return review


def review_findings(
    review: dict[str, Any], source: str, parent_issue: str | None = None
) -> list[dict[str, Any]]:
    findings = []
    for item in review.get("findings", []):
        findings.append(
            {
                **item,
                "fingerprint": [
                    source,
                    parent_issue,
                    item["category"],
                    item["title"],
                    sorted(item["files"]),
                ],
                "source": source,
                "source_version": None,
                "parent_issue": parent_issue,
            }
        )
    return findings


def _validate_review(review: dict[str, Any], mode: str) -> None:
    extra_top_level = review.keys() - {
        "verdict", "summary", "findings", "declared_changes_assessed", "verification_token", "reviewed_files"
    }
    if extra_top_level:
        raise RuntimeError(
            "review output has unsupported fields: " + ", ".join(sorted(extra_top_level))
        )
    token = review.get("verification_token")
    if token is not None and (not isinstance(token, str) or not token):
        raise RuntimeError("review verification_token must be a non-empty string or null")
    if "reviewed_files" in review and (
        not isinstance(review["reviewed_files"], list)
        or any(not isinstance(path, str) or not path.strip()
               or Path(path).is_absolute() or ".." in Path(path).parts for path in review["reviewed_files"])
    ):
        raise RuntimeError("reviewed_files must be an array of non-empty repository-relative paths")
    expected = {"initial": {"reviewed"}, "prevention": {"pass", "fail"}}.get(mode, {"pass", "partial", "fail"})
    verdict = review.get("verdict")
    if verdict not in expected:
        raise RuntimeError(f"review verdict {verdict!r} is invalid for {mode}")
    if not isinstance(review.get("summary"), str) or not review["summary"]:
        raise RuntimeError("review output must contain a non-empty summary")
    if not isinstance(review.get("findings"), list):
        raise RuntimeError("review output must contain a findings array")
    if len(review["findings"]) > 12:
        raise RuntimeError("review output may contain at most 12 findings")
    if "reviewed_files" not in review:
        raise UnverifiableReview("review omitted reviewed_files; inspection evidence is unknown and coverage is zero")
    if not review["reviewed_files"] and (not review["findings"] or verdict == "pass"):
        raise UnverifiableReview("review inspected no files; evidence is unknown")
    assessments = review.get("declared_changes_assessed", [])
    if not isinstance(assessments, list):
        raise RuntimeError("review output declared_changes_assessed must be an array")
    for index, assessment in enumerate(assessments):
        fields = {"note", "verdict", "evidence"}
        if not isinstance(assessment, dict) or not fields <= assessment.keys() <= fields | {"note_id"}:
            raise RuntimeError(f"declared change assessment {index} has invalid fields")
        if "note_id" in assessment and (not isinstance(assessment["note_id"], str) or not assessment["note_id"]):
            raise RuntimeError(f"declared change assessment {index}.note_id must be non-empty")
        if assessment.get("verdict") not in {"accepted", "rejected"}:
            raise RuntimeError(f"declared change assessment {index}.verdict is invalid")
        if not isinstance(assessment.get("note"), str) or not assessment["note"]:
            raise RuntimeError(f"declared change assessment {index}.note must be non-empty")
        if not isinstance(assessment.get("evidence"), list) or not assessment["evidence"] or not all(
            isinstance(value, str) and value for value in assessment["evidence"]
        ):
            raise RuntimeError(f"declared change assessment {index}.evidence must be a non-empty string array")
    if verdict == "pass" and any(item["verdict"] == "rejected" for item in assessments):
        raise RuntimeError("a passing post-fix review cannot contain a rejected declared change")
    for index, finding in enumerate(review["findings"]):
        if not isinstance(finding, dict):
            raise RuntimeError(f"review finding {index} must be an object")
        missing = REVIEW_FINDING_FIELDS - finding.keys()
        if missing:
            raise RuntimeError(
                f"review finding {index} is missing: {', '.join(sorted(missing))}"
            )
        extra = finding.keys() - REVIEW_FINDING_FIELDS
        if extra:
            raise RuntimeError(
                f"review finding {index} has unsupported fields: {', '.join(sorted(extra))}"
            )
        for field in ("category", "title", "harm", "proposed_change", "risk", "priority", "confidence", "chesterton"):
            if not isinstance(finding[field], str) or not finding[field]:
                raise RuntimeError(f"review finding {index}.{field} must be a non-empty string")
        for field in ("evidence", "files", "symbols", "invariants", "verification"):
            if not isinstance(finding[field], list) or not all(
                isinstance(value, str) and value for value in finding[field]
            ):
                raise RuntimeError(f"review finding {index}.{field} must be a string array")
        if not all(
            finding[field] for field in ("evidence", "files", "invariants", "verification")
        ):
            raise RuntimeError(
                f"review finding {index} needs evidence, files, invariants, and verification"
            )
        choices = {
            "category": REVIEW_CATEGORIES,
            "risk": {"low", "medium", "high"},
            "priority": {"P0", "P1", "P2", "P3"},
            "confidence": {"low", "medium", "high"},
        }
        for field, allowed in choices.items():
            if finding[field] not in allowed:
                raise RuntimeError(f"review finding {index}.{field} is invalid")
    if mode in {"post_fix", "prevention"} and verdict == "fail" and not review["findings"]:
        raise RuntimeError(f"a failing {mode.replace('_', '-')} review must include an actionable finding")
    if mode in {"post_fix", "prevention"} and verdict == "pass" and any(
        finding["priority"] in {"P0", "P1"} for finding in review["findings"]
    ):
        raise RuntimeError(f"a passing {mode.replace('_', '-')} review cannot include a P0 or P1 finding")


def validate_note_assessments(review: dict[str, Any], notes: list[dict[str, Any]]) -> None:
    if any(not isinstance(note, dict) or not isinstance(note.get("id"), str) or not note["id"] for note in notes):
        raise RuntimeError("legacy notes lack stable IDs; run `hangover verify` again")
    required = {note["id"] for note in notes}
    assessed = [item.get("note_id") for item in review.get("declared_changes_assessed", [])]
    if any(identifier not in required for identifier in assessed):
        raise RuntimeError("declared change assessment must reference an issued note_id")
    if len(assessed) != len(set(assessed)):
        raise RuntimeError("declared change assessment repeats a note_id")
    if review["verdict"] == "pass" and set(assessed) != required:
        raise RuntimeError("passing review is missing required note assessments")


def _item_paths(item: dict[str, Any]) -> list[str]:
    paths: set[str] = set()
    for key in ("path", "file", "source", "target"):
        value = item.get(key)
        if isinstance(value, str) and value:
            paths.add(value)
    values = item.get("files")
    if isinstance(values, list):
        paths.update(value for value in values if isinstance(value, str) and value)
    return sorted(paths)


def _item_symbols(item: dict[str, Any]) -> list[str]:
    values = []
    for key in ("export_name", "type_name", "member_name", "package_name", "symbol"):
        value = item.get(key)
        if isinstance(value, str) and value:
            values.append(value)
    return values


def _duplication_title(line_count: Any, files: list[str], instance_count: int) -> str:
    line_label = "line" if line_count == 1 else "lines"
    prefix = f"Consolidate {line_count} duplicated {line_label}"
    if len(files) == 1:
        repetitions = "twice" if instance_count == 2 else f"{instance_count} times"
        return f"{prefix} repeated {repetitions} within {files[0]}"
    if len(files) == 2:
        return f"{prefix} shared by {files[0]} and {files[1]}"
    listed_files = ", ".join(files[:3])
    if len(files) > 3:
        listed_files += f", +{len(files) - 3} more"
    return f"{prefix} shared by {len(files)} files ({listed_files})"


FINDING_ID_PATTERN = re.compile(r"dc[0-9]+:[a-z0-9-]+:[0-9a-f]+(?:~[0-9]+)?")


def _fallow_finding_id(item: dict[str, Any]) -> str | None:
    value = item.get("finding_id")
    return value if isinstance(value, str) and FINDING_ID_PATTERN.fullmatch(value) else None


def _finding_key(field: str, item: dict[str, Any]) -> list[Any]:
    return [field, _item_paths(item), _item_symbols(item)]


def _subject(item: dict[str, Any], paths: list[str]) -> str:
    symbols = _item_symbols(item)
    if symbols and paths:
        return f"{', '.join(symbols)} in {', '.join(paths)}"
    if symbols:
        return ", ".join(symbols)
    if paths:
        return ", ".join(paths)
    return "an analyzer-reported item"


def _harm(field: str) -> str:
    if "circular" in field or "cycle" in field:
        return "The dependency cycle obscures initialization and change impact across modules."
    if "boundary" in field or "policy" in field:
        return "The import path bypasses an intended architecture seam and spreads knowledge across modules."
    if "unresolved" in field or "unlisted" in field:
        return "The dependency contract is incomplete and can fail outside the current environment."
    if "dependencies" in field:
        return "The manifest advertises machinery the reachable program may not use."
    return "Unreachable surface adds concepts, maintenance cost, and misleading change points without present value."


def _proposed_change(field: str) -> str:
    if "circular" in field or "cycle" in field:
        return "Identify the shared primitive or misplaced responsibility that closes the cycle, then make dependencies one-way."
    if "boundary" in field or "policy" in field:
        return "Move the behavior to the owning module or route the call through the existing intended seam."
    if "unresolved" in field or "unlisted" in field:
        return "Repair the dependency declaration or import rather than suppressing the finding."
    return "Trace runtime and external use, then delete or narrow the item if no present requirement depends on it."


def _priority_bump_hotspot_paths(health: dict[str, Any]) -> set[str]:
    if (health.get("hotspot_summary") or {}).get("clock", {}).get("reproducible") is False:
        return set()
    hotspots = health.get("hotspots")
    vital_signs = health.get("vital_signs")
    if not isinstance(hotspots, list) or not isinstance(vital_signs, dict):
        return set()
    top_count = vital_signs.get("hotspot_top_pct_count")
    if isinstance(top_count, bool) or not isinstance(top_count, int) or top_count <= 0:
        return set()
    return {
        path
        for hotspot in hotspots[:top_count]
        if isinstance(hotspot, dict)
        and isinstance((path := hotspot.get("path")), str)
        and path
        and str(hotspot.get("trend", "")).lower() != "cooling"
    }


def _complexity_findings(health: Any, repo: Path | None = None,
                         function_inventory: Any = None) -> list[dict[str, Any]]:
    if not isinstance(health, dict):
        return []
    raw_summary = health.get("summary")
    summary = raw_summary if isinstance(raw_summary, dict) else {}
    max_cyclomatic = summary.get("max_cyclomatic_threshold")
    if max_cyclomatic is None:
        max_cyclomatic = 20
    max_cognitive = summary.get("max_cognitive_threshold")
    if max_cognitive is None:
        max_cognitive = 15
    hotspot_by_path: dict[str, dict[str, Any]] = {}
    hotspots = health.get("hotspots")
    if isinstance(hotspots, list):
        for hotspot in hotspots:
            if not isinstance(hotspot, dict):
                continue
            path = hotspot.get("path")
            if isinstance(path, str) and path and path not in hotspot_by_path:
                hotspot_by_path[path] = hotspot
    priority_bump_hotspot_paths = _priority_bump_hotspot_paths(health)
    findings: list[dict[str, Any]] = []
    items = health.get("findings")
    if not isinstance(items, list):
        return findings
    for item in items:
        finding = _complexity_finding(
            item,
            max_cyclomatic,
            max_cognitive,
            hotspot_by_path,
            priority_bump_hotspot_paths,
        )
        if finding is not None:
            if ((health.get("hotspot_summary") or {}).get("clock", {}).get("reproducible") is False
                    and item.get("path") in hotspot_by_path):
                finding["evidence"].append("Hotspot evidence is advisory: its clock is not reproducible; no priority bump.")
            findings.append(finding)
    assign_complexity_identities(findings, repo, function_inventory)
    return findings


def _complexity_finding(
    item: Any,
    max_cyclomatic: Any,
    max_cognitive: Any,
    hotspot_by_path: dict[str, dict[str, Any]],
    priority_bump_hotspot_paths: set[str],
) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    path = item.get("path")
    if not isinstance(path, str) or not path:
        return None
    name = item.get("name")
    if not isinstance(name, str) or not name:
        name = "unnamed function"
    exceeded = item.get("exceeded", "unknown")
    if not isinstance(exceeded, str):
        exceeded = "unknown"
    hotspot = hotspot_by_path.get(path)
    severity = item.get("severity")
    coverage_measured = item.get("coverage_source") == "istanbul"
    estimated_crap_only = exceeded == "crap" and not coverage_measured
    if estimated_crap_only:
        priority = "P3"
        confidence = "low"
    else:
        priority = (
            {"critical": "P1", "high": "P2", "moderate": "P3"}.get(severity, "P3")
            if isinstance(severity, str)
            else "P3"
        )
        confidence = "high"
    priority_before_hotspot = priority
    if not estimated_crap_only and path in priority_bump_hotspot_paths:
        priority = {"P3": "P2", "P2": "P1"}.get(priority, priority)
    priority_raised = priority != priority_before_hotspot
    evidence = []
    if estimated_crap_only:
        evidence.append(
            "CRAP is computed from estimated coverage; wire an Istanbul report into "
            "Fallow `health.coverage` for a real score."
        )
    evidence.append(
        (
            f"Fallow {FALLOW_VERSION} measured {name} in {path}:{item.get('line', '?')} "
            f"at cyclomatic {item.get('cyclomatic', '?')} and cognitive {item.get('cognitive', '?')} "
            f"(thresholds {max_cyclomatic}/{max_cognitive}); exceeded: {exceeded}."
        )
    )
    crap = item.get("crap")
    if crap is not None:
        coverage_kind = "measured" if coverage_measured else "estimated"
        coverage_pct = item.get("coverage_pct")
        coverage_text = f"{coverage_pct}%" if coverage_pct is not None else "unknown"
        evidence.append(
            f"CRAP score {crap} with coverage {coverage_text}; "
            f"coverage was {coverage_kind}."
        )
    actions = item.get("actions")
    if not isinstance(actions, list):
        actions = []
    for action in actions:
        if isinstance(action, dict) and action.get("description"):
            evidence.append(str(action["description"]))
            break
    if hotspot:
        evidence.append(
            f"Fallow hotspot score {hotspot.get('score', '?')} "
            f"({hotspot.get('commits', '?')} commits, trend {hotspot.get('trend', '?')})."
        )
    if priority_raised and hotspot:
        evidence.append(
            f"Priority raised one level: {path} is a top-tier Fallow hotspot "
            f"({hotspot.get('score', '?')}, {hotspot.get('commits', '?')} commits, "
            f"trend {hotspot.get('trend', '?')})."
        )
    suppression = next(
        (
            {"config_key": action["config_key"], "value": action["value"]}
            for action in actions
            if isinstance(action, dict)
            and action.get("type") == "add-to-config"
            and action.get("config_key")
            and action.get("value")
        ),
        None,
    )
    return {
        "fingerprint": ["fallow", "complexity", path, name],
        "complexity_identity": {"family": [path, name], "line": item.get("line"),
                                "col": item.get("col"), "line_count": item.get("line_count")},
        "complexity_metrics": {
            **{key: item[key] for key in ("cyclomatic", "cognitive", "crap", "line_count")
               if isinstance(item.get(key), (int, float)) and not isinstance(item.get(key), bool)},
            "max_cyclomatic": max_cyclomatic, "max_cognitive": max_cognitive,
        },
        "source": "fallow",
        "source_version": FALLOW_VERSION,
        "category": "complexity",
        "title": f"Reduce complexity of {name} in {path}",
        **({"suppression": suppression} if suppression else {}),
        "evidence": evidence,
        "files": [path],
        "symbols": [name],
        "harm": "A function this complex resists safe modification: every branch multiplies the states a maintainer must hold in mind, and defects hide in the interactions.",
        "proposed_change": "Extract coherent sub-steps behind existing seams, flatten nesting with early returns, and split policy from mechanics — without changing any observable behavior.",
        "invariants": [
            "Every caller observes identical inputs, outputs, side effects, and error behavior.",
            "No test is weakened or deleted to make the refactor pass.",
        ],
        "risk": "medium",
        "priority": priority,
        "confidence": confidence,
        "verification": [
            "Run the narrowest tests covering the function, then the repository's configured full gate.",
            "Re-scan and confirm the function's complexity dropped without new findings elsewhere.",
        ],
        "chesterton": "High complexity sometimes encodes essential domain policy; identify which branches are essential before extracting or collapsing any of them.",
    }
