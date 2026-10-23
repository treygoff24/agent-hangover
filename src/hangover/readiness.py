"""Resolve and check a review route before spending the repository's gate."""
from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from .model import paths, write_json
from .oracles import (
    TOOL_ROOT, codex_binary, delegate_review_command, review_environment,
    substitute_command_template, runner_environment_failure,
)
from .process import run_logged
from .repository import diagnostic_text, git_safe_environment

REVIEW_RUNNERS = ("codex", "delegate", "command", "none")
# Every review-running command (run, review, verify, audit --require-review)
# takes --runner, and review.runner in .hangover/config.json sets the default.
OTHER_REVIEWERS = (
    "choose another reviewer with --runner command (your own review command, set in review.command) "
    "or --runner delegate, or --runner none to only prepare the review packet for a reviewer you run "
    "yourself (`hangover review --prepare`, then `hangover review --import`); review.runner in "
    ".hangover/config.json changes the default, and `hangover run --no-review` skips the review"
)


def command_binary(template: Any, repo: Path) -> Path | None:
    """Resolve a configured executable without executing repository code."""
    if not isinstance(template, list) or not template or not isinstance(template[0], str):
        return None
    value = template[0]
    candidate = Path(value).expanduser()
    if os.sep in value or candidate.is_absolute():
        candidate = (candidate if candidate.is_absolute() else repo / candidate).resolve()
        return candidate if candidate.is_file() and os.access(candidate, os.X_OK) else None
    found = shutil.which(value)
    return Path(found).resolve() if found else None


def codex_auth_state(binary: Path) -> str:
    """Local login status is credential presence, never an online validity probe."""
    with tempfile.TemporaryDirectory(prefix="hangover-auth-preflight-") as directory:
        root = Path(directory)
        result = run_logged([str(binary), "login", "status"], cwd=TOOL_ROOT, env=git_safe_environment(),
                            stdout_path=root / "stdout", stderr_path=root / "stderr",
                            timeout_seconds=10, max_output_bytes=32 * 1024)
        text = (result.stdout_tail + "\n" + (result.stderr_tail or "")).casefold()
        error = runner_environment_failure(text)
        if error:
            raise RuntimeError(error)
        if "not logged in" in text:
            return "not_logged_in"
        if result.status != "exited" or result.exit_code != 0:
            raise RuntimeError("Codex local login status could not be checked; run `hangover doctor`, or " + OTHER_REVIEWERS)
        return "logged_in" if "logged in" in text else "unknown"


def codex_startup_probe(binary: Path) -> dict[str, Any]:
    """Start the read-only shell sandbox locally; never invoke a model."""
    with tempfile.TemporaryDirectory(prefix="hangover-runner-probe-") as directory:
        root = Path(directory)
        # sandbox has no --ignore-user-config on some supported CLIs. An
        # empty run-local Codex home excludes user config without a model or
        # access to credentials; managed host restrictions still apply.
        config_home = root / "codex-home"
        config_home.mkdir()
        environment = {**git_safe_environment(), "CODEX_HOME": str(config_home)}
        def capture(command: list[str]):
            return run_logged(command, cwd=TOOL_ROOT, env=environment,
                              stdout_path=root / "stdout", stderr_path=root / "stderr",
                              timeout_seconds=10, max_output_bytes=32 * 1024)

        help_result = capture([str(binary), "sandbox", "--help"])
        if help_result.status != "exited" or help_result.exit_code != 0:
            error = runner_environment_failure(help_result.stdout_tail + "\n" + (help_result.stderr_tail or ""))
            raise RuntimeError(error or "Codex runner startup is unverifiable: sandbox help unavailable; " + OTHER_REVIEWERS)
        # New Codex uses built-in permission profiles; older versions use an
        # OS subcommand. Ask the installed CLI rather than guessing by version.
        if "--permission-profile" in help_result.stdout_tail:
            options = ["--permission-profile", ":read-only", "-C", str(TOOL_ROOT)]
        elif sys.platform in {"linux", "darwin"}:
            options = ["linux" if sys.platform == "linux" else "macos", "-c", 'sandbox_mode="read-only"', "--"]
        else:
            raise RuntimeError("Codex runner startup probe is unavailable on this platform; " + OTHER_REVIEWERS)
        result = capture([str(binary), "sandbox", *options, "/bin/sh", "-c", "printf hangover-runner-probe"])
        error = runner_environment_failure(result.stdout_tail + "\n" + (result.stderr_tail or ""))
        if error:
            raise RuntimeError(error)
        if result.status != "exited" or result.exit_code != 0 or "hangover-runner-probe" not in result.stdout_tail.split():
            raise RuntimeError("Codex runner cannot execute here: " + diagnostic_text(result.stdout_tail, result.stderr_tail or result.status))
        return {"status": "ready", "sandbox": "read-only", "model_invoked": False}


def delegate_preflight(repo: Path, plan: dict[str, Any]) -> dict[str, Any]:
    """Delegate's dry-run resolves profiles, transport and model configuration;
    it does not launch a model. Keep only public route metadata from its reply."""
    with tempfile.TemporaryDirectory(prefix="review-preflight-", dir=paths(repo)["root"]) as directory:
        root = Path(directory)
        prompt = root / "prompt.md"
        prompt.write_text("Read-only review readiness probe. No model invocation.\n")
        schema = TOOL_ROOT / "schemas/review.schema.json"
        options = plan["delegate"]
        if options["lane"] == "claude":
            value = json.loads(schema.read_text())
            value.pop("$schema", None)
            schema = root / "review.schema.json"
            write_json(schema, value)
        command = delegate_review_command(prompt, schema, plan["timeout_seconds"], **options)
        command.insert(2, "dry-run")
        result = run_logged(command, cwd=repo, env=review_environment(plan["env"]),
                            stdout_path=root / "stdout", stderr_path=root / "stderr",
                            timeout_seconds=30, max_output_bytes=512 * 1024)
        stdout = (root / "stdout").read_text(errors="replace")
        if result.status != "exited" or result.exit_code != 0:
            raise RuntimeError("Delegate preflight failed: " + diagnostic_text(stdout, result.stderr_tail or "", plan["env"]))
        try:
            value = json.loads(stdout)
        except ValueError as exc:
            raise RuntimeError("Delegate preflight did not return JSON") from exc
        if (not isinstance(value, dict) or value.get("ok") is not True or value.get("dryRun") is not True
                or value.get("mode") != "safe"):
            raise RuntimeError("Delegate preflight did not confirm a safe dry-run")
        engine = value.get("engine")
        if not isinstance(engine, str) or not engine:
            raise RuntimeError("Delegate preflight did not identify its engine")
        if options["lane"] in {"codex", "claude"} and engine != options["lane"]:
            raise RuntimeError("Delegate preflight changed the explicitly selected engine")
        reported_model = value.get("modelResolved") or value.get("model")
        reported_effort = value.get("resolvedReasoningEffort")
        if options["model"] is not None and (not isinstance(reported_model, str) or not reported_model):
            raise RuntimeError("Delegate preflight did not confirm the requested model")
        requested_effort = options["reasoning_effort"]
        if requested_effort is not None and (not isinstance(reported_effort, str)
                or reported_effort.casefold() != requested_effort.casefold()):
            raise RuntimeError("Delegate preflight changed or omitted the requested reasoning effort")
        return {"status": "ready", "engine": engine, "model": reported_model,
                "reasoning_effort": reported_effort,
                "prompt_transport": value.get("promptTransport"), "credential_validity": "not_probed"}


def resolve_review(
    repo: Path, settings: dict[str, Any], *, runner: str | None = None,
    lane: str | None = None, model: str | None = None, reasoning_effort: str | None = None,
    execute: bool = True,
) -> dict[str, Any]:
    plan = copy.deepcopy(settings)
    plan["runner"] = runner or plan["runner"]
    if plan["runner"] not in REVIEW_RUNNERS:
        raise RuntimeError(f"unsupported review runner {plan['runner']!r}")
    if any(value is not None for value in (lane, model, reasoning_effort)) and plan["runner"] != "delegate":
        raise RuntimeError("--lane, --model, and --reasoning-effort require the delegate review runner")
    for key, value in (("lane", lane), ("model", model), ("reasoning_effort", reasoning_effort)):
        if value is not None:
            plan["delegate"][key] = value
    timeout = plan["timeout_seconds"]
    try:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, str)):
            raise ValueError
        timeout = int(timeout)
        if timeout <= 0:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise RuntimeError("review.timeout_seconds must be a positive integer") from exc
    plan["timeout_seconds"] = timeout
    plan["requested"] = {"runner": plan["runner"]}
    if plan["runner"] == "delegate":
        plan["requested"].update(plan["delegate"])
    plan["preflight"] = {"status": "not_invoked", "credential_validity": "not_probed"}
    if not execute or plan["runner"] == "none":
        return plan
    if plan["runner"] == "command":
        substitute_command_template(plan["command"], repo, Path("prompt"), Path("output"), Path("schema"))
        binary = command_binary(plan["command"], repo)
        if binary is None:
            raise RuntimeError("review.command executable is unavailable; fix the configured path before running gates")
        plan["preflight"] = {"status": "ready", "binary": str(binary), "credential_validity": "not_probed"}
    elif plan["runner"] == "codex":
        binary = codex_binary()
        if binary is None:
            raise RuntimeError("no usable Codex binary (install the Codex CLI, or set HANGOVER_CODEX_BIN); " + OTHER_REVIEWERS)
        auth_state = codex_auth_state(binary)
        if auth_state == "not_logged_in":
            raise RuntimeError("Codex is not logged in, so the default reviewer cannot run and nothing has run yet; "
                               "run `codex login`, or " + OTHER_REVIEWERS)
        startup = codex_startup_probe(binary)
        plan["preflight"] = {"status": "ready", "binary": str(binary), "local_auth_state": auth_state,
                             "credential_validity": "not_probed", "startup": startup}
    else:
        plan["preflight"] = delegate_preflight(repo, plan)
        if plan["delegate"]["lane"] == "codex":
            binary = codex_binary()
            if binary is not None:
                plan["preflight"]["startup"] = codex_startup_probe(binary)
        for field in ("model", "reasoning_effort"):
            resolved = plan["preflight"].get(field)
            if isinstance(resolved, str) and resolved:
                plan["delegate"][field] = resolved
    plan["preflight"]["forwarded_env_present"] = [name for name in plan["env"] if os.environ.get(name)]
    return plan
