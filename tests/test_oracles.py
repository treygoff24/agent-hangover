import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hangover.oracles import (
    DEAD_CODE_FIELDS,
    DEAD_CODE_RULE_BY_FIELD,
    TOOL_ROOT,
    FALLOW_VERSION,
    codex_review_command,
    run_codex_review,
    delegate_binary,
    delegate_review_command,
    parse_delegate_review,
    extract_fallow_findings,
    fallow_dead_code_mode,
    import_review,
    review_findings,
    run_command_review,
    run_delegate_review,
    run_fallow_scan,
    run_fallow_audit,
    substitute_command_template,
    summarize_fallow,
    validate_note_assessments,
)
from hangover.repository import git_safe_environment
from hangover.process import RunResult
from hangover.model import merge_findings, new_state


def logged_result(completed):
    """A process-protocol fixture: writes the artifacts a real capture writes."""
    def run(command, **kwargs):
        result = completed(command, **kwargs) if callable(completed) else completed
        stdout, stderr = result.stdout or "", result.stderr or ""
        Path(kwargs["stdout_path"]).write_text(stdout)
        Path(kwargs["stderr_path"]).write_text(stderr)
        return RunResult("exited", result.returncode, 0.01, str(kwargs["stdout_path"]), str(kwargs["stderr_path"]),
                         len(stdout.encode()), len(stderr.encode()), stdout[-8192:], stderr[-8192:], False)
    return run


CODEX_ASSISTANT_TEXT = '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"I’ll first load the repository instructions and the relevant review/hangover guidance, then inspect only src/lib and src/components for up to three concrete slop findings.","findings":[]}\n\n{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"Repository guidance and the code-review/hangover instructions are loaded. I’m now mapping src/lib and src/components, then I’ll inspect likely duplication, dead machinery, and unnecessary indirection without changing files.","findings":[]}\n\n{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"Reviewed src/lib and src/components for dead machinery, duplicated concepts, and needless indirection. Found three scoped maintainability issues; no files were changed.","findings":[{"category":"dead_code","title":"Unused heading-ID normalizer is dead machinery","evidence":["`withHeadingIds` is exported in `src/lib/articles.ts` but has no call sites anywhere in the repository."],"files":["src/lib/articles.ts"],"symbols":["withHeadingIds"],"harm":"Adds an apparently canonical transformation that is never applied.","proposed_change":"Delete the helper if it is not an external API.","invariants":["Rendered heading IDs remain unchanged."],"risk":"low","priority":"P2","confidence":"high","verification":["Repository-wide search finds no callers."],"chesterton":"Confirm there is no external package consumer before deleting it."}]}'

GLM_ASSISTANT_TEXT = '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"Found 3 instances of code slop in src/lib and src/components: duplicated form field components across 6 forms.","findings":[{"category":"duplication","title":"Duplicated Form Field Components","evidence":["ContactForm.tsx defines a Field component with label, input, and error handling."],"files":["src/components/forms/ContactForm.tsx"],"symbols":["Field"],"harm":"Changes require updating multiple files.","proposed_change":"Extract a shared FormField component.","invariants":["All form fields retain their accessibility attributes."],"risk":"low","priority":"P2","confidence":"high","verification":["Run existing form tests."],"chesterton":"Preserve form-specific props."}]}\n\n**Completion Report**\n\n- **Status:** completed\n- **What I did:** Reviewed the form components.\n- **Remaining risks:** The duplicated form patterns increase maintenance burden, including {braces}.'

TRUNCATED_STRING_ASSISTANT_TEXT = (
    '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"planning","findings":[]}\n\n'
    '{"verdict":"reviewed","summary":"Reviewed src/lib and found real work.",'
    '"findings":[{"category":"dead_code","title":"Unused heading-ID normal'
)

TRUNCATED_OBJECT_ASSISTANT_TEXT = (
    '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"planning","findings":[]}\n\n'
    '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"Reviewed src/lib and found real work.","findings":[]'
)


class OracleTests(unittest.TestCase):
    def test_unused_dev_dependency_counts_are_complete(self):
        dead = json.loads((Path(__file__).parent / "fixtures/fallow-unused-dev-dependency.json").read_text())
        self.assertEqual("completed", self.scan_payload(dead)["status"])
        dead["summary"]["unused_dependencies"] += 1
        self.assertEqual("partial", self.scan_payload(dead)["status"])
        dead["summary"]["unused_dependencies"] -= 1
        dead["unused_dev_dependencies"] = ["malformed"]
        self.assertEqual("partial", self.scan_payload(dead)["status"])

    def test_reviewed_files_reject_absolute_and_traversal_paths(self):
        from hangover.oracles import _validate_review
        for mode in ("post_fix", "prevention"):
            for path in ("/outside.rs", "../outside.rs", "src/../../outside.rs"):
                with self.subTest(mode=mode, path=path), self.assertRaisesRegex(RuntimeError, "repository-relative"):
                    _validate_review({"verdict": "pass", "summary": "done", "findings": [],
                                      "reviewed_files": [path]}, mode)

    def test_partial_review_is_a_valid_non_approval(self):
        from hangover.oracles import _validate_review
        review = {"verdict": "partial", "summary": "Five cited locations remain.",
                  "reviewed_files": ["src/lib.rs"], "findings": []}
        _validate_review(review, "post_fix")
        for mode in ("initial", "prevention"):
            with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, f"invalid for {mode}"):
                _validate_review(review, mode)

    def test_review_finding_limit_is_twelve(self):
        from hangover.oracles import _validate_review
        finding = json.loads(GLM_ASSISTANT_TEXT.split("\n\n")[0])["findings"][0]
        review = {"verdict": "reviewed", "summary": "done", "reviewed_files": ["src/lib.rs"],
                  "findings": [finding] * 12}
        _validate_review(review, "initial")
        review["findings"].append(finding)
        with self.assertRaisesRegex(RuntimeError, "at most 12"):
            _validate_review(review, "initial")

    def test_review_packet_has_no_rust_evidence_without_a_snapshot(self):
        from hangover.oracles import prepare_review_packet
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for snapshot in ({}, {"rust": None}, {"rust": {}}):
                with self.subTest(snapshot=snapshot):
                    packet = prepare_review_packet(root, root, "post_fix", snapshot)
                    self.assertIsNone(json.loads(packet.read_text())["rust"])

    def test_codex_workspace_is_outside_target_and_removed_after_capture(self):
        for outcome in ("completed", "failed", "exception"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                repo = Path(directory).resolve()
                subprocess.run(["git", "init", "-q", repo], check=True)
                (repo / "AGENTS.md").write_text("TARGET INSTRUCTIONS ARE UNTRUSTED")
                run_dir = repo / ".hangover" / "runs" / "review"
                run_dir.mkdir(parents=True)
                (run_dir / "review-prompt.md").write_text("Review the supplied evidence only.")
                workspaces = []
                def capture(command, cwd, stdout, stderr, *args, **kwargs):
                    cwd = Path(cwd)
                    workspaces.append(cwd)
                    self.assertFalse(cwd.is_relative_to(repo), f"workspace is inside target: {cwd}")
                    self.assertEqual(str(cwd), command[command.index("-C") + 1])
                    self.assertIn("project_doc_max_bytes=0", command)
                    self.assertTrue(cwd.is_dir())
                    self.assertEqual([], list(cwd.iterdir()))
                    if outcome == "exception":
                        raise OSError("capture failed")
                    Path(stderr).write_text("")
                    (run_dir / "review.json").write_text(json.dumps({"verdict": "reviewed", "summary": "done",
                        "findings": [], "reviewed_files": ["file.py"]}))
                    return {"status": outcome, "exit_code": 0 if outcome == "completed" else 1}
                with patch("hangover.oracles.codex_binary", return_value=Path("/usr/bin/codex")), patch(
                    "hangover.oracles._capture", side_effect=capture
                ):
                    if outcome == "exception":
                        with self.assertRaisesRegex(OSError, "capture failed"):
                            run_codex_review(repo, run_dir, run_dir / "packet.json", "initial")
                    else:
                        result = run_codex_review(repo, run_dir, run_dir / "packet.json", "initial")
                        self.assertEqual(outcome, result["status"])
                self.assertEqual(1, len(workspaces))
                self.assertFalse(workspaces[0].exists())

    def test_rust_evidence_reaches_fresh_packet_and_inline_transport(self):
        from hangover.oracles import prepare_review_packet, _delegate_prompt
        rust = {"status": "partial", "version": "hangover-rust 1", "tools": {"clippy": "clippy 1"},
                "sections": {"clippy": "failed"}, "warnings": ["clippy failed"],
                "summary": {"findings": 1}, "commands": {"clippy": {"stdout": "/run/clippy.out", "stderr": "/run/clippy.err"}},
                "findings": [{"title": "RUST-CONTEXT"}]}
        comparison = {"comparable": False, "reason": "clippy failed"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packet_path = prepare_review_packet(root, root, "post_fix", {"rust": rust, "rust_comparison": comparison})
            packet = json.loads(packet_path.read_text())
            self.assertEqual({key: rust[key] for key in ("status", "version", "tools", "sections", "warnings", "summary")},
                             {key: packet["rust"][key] for key in ("status", "version", "tools", "sections", "warnings", "summary")})
            self.assertEqual({"clippy": {"stdout": "/run/clippy.out", "stderr": "/run/clippy.err"}}, packet["rust"]["raw_artifacts"])
            self.assertEqual(comparison, packet["rust_comparison"])
            prompt = _delegate_prompt("Review", root / "review-schema.json", packet_path)
            self.assertIn('"rust_comparison"', prompt)
            self.assertIn('"clippy failed"', prompt)
            audit = {"status": "partial", "verdict": None, "current": rust,
                     "base": {"status": "completed"}, "introduced": [{"title": "introduced"}]}
            packet_path = prepare_review_packet(root, root, "prevention", {"rust": audit})
            packet = json.loads(packet_path.read_text())
            self.assertEqual("partial", packet["rust"]["current"]["status"])
            self.assertEqual(audit["introduced"], packet["rust"]["introduced"])
            self.assertEqual({"clippy": {"stdout": "/run/clippy.out", "stderr": "/run/clippy.err"}}, packet["rust"]["current"]["raw_artifacts"])

    def test_codex_records_reported_model_effort_and_uses_empty_cwd(self):
        warning = "WARNING: proceeding, even though we could not create PATH aliases: Permission denied\n"
        for prefix, header, model, effort in (("", "model: review-model\nreasoning effort: high\n", "review-model", "high"),
                                              (warning, "model: review-model\nreasoning effort: high\n", "review-model", "high"),
                                              (warning, "", None, None)):
            with self.subTest(prefix=prefix, header=header), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo, run_dir = root / "repo", root / "run"
                repo.mkdir()
                run_dir.mkdir()
                (run_dir / "review-prompt.md").write_text("model: prompt-spoof\nreasoning effort: low\n")
                (run_dir / "review.json").write_text(json.dumps({"verdict": "reviewed", "summary": "done",
                                                               "findings": [], "reviewed_files": ["file.py"]}))
                stderr = (prefix + "OpenAI Codex v0.test\n--------\nworkdir: /run\n" + header +
                          "--------\nuser\nmodel: prompt-spoof\nreasoning effort: low\n")
                def completed(command, **kwargs):
                    cwd = Path(kwargs["cwd"])
                    self.assertEqual(str(cwd), command[command.index("-C") + 1])
                    self.assertFalse(cwd.is_relative_to(repo))
                    self.assertTrue(cwd.is_dir())
                    self.assertEqual([], list(cwd.iterdir()))
                    return subprocess.CompletedProcess(command, 0, "", stderr)
                with patch("hangover.oracles.codex_binary", return_value=Path("/usr/bin/codex")), patch(
                    "hangover.oracles.run_logged", side_effect=logged_result(completed)
                ):
                    result = run_codex_review(repo, run_dir, root / "packet.json", "initial")
                self.assertEqual("completed", result["status"])
                self.assertEqual(model, result["model"])
                self.assertEqual(effort, result["reasoning_effort"])

    def test_fallow_version_is_cached_per_binary(self):
        from hangover.oracles import fallow_version, _fallow_version_of
        _fallow_version_of.cache_clear()
        self.addCleanup(_fallow_version_of.cache_clear)
        with patch("hangover.oracles._fallow_path", side_effect=[Path("/fallow-a"), Path("/fallow-a"), Path("/fallow-b")]), patch(
            "hangover.oracles.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "fallow 3.31.0\n", "")
        ) as run:
            self.assertEqual("fallow 3.31.0", fallow_version())
            self.assertEqual("fallow 3.31.0", fallow_version())
            self.assertEqual("fallow 3.31.0", fallow_version())
            self.assertEqual(2, run.call_count)

    def test_manual_import_refuses_unperformed_review_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.json"
            for mode, verdict in (("initial", "reviewed"), ("post_fix", "pass"), ("prevention", "pass")):
                for files in ([], None):
                    for summary in ("Reviewed code", "Couldn't perform the review", "Unable to perform a review"):
                        with self.subTest(mode=mode, files=files, summary=summary):
                            review = {"verdict": verdict, "summary": summary, "findings": []}
                            if files is not None:
                                review["reviewed_files"] = files
                            output.write_text(json.dumps(review))
                            with self.assertRaisesRegex(RuntimeError, "unknown"):
                                import_review(output, mode)
                output.write_text(json.dumps({"verdict": verdict,
                                              "summary": "Could not inspect the live service; reviewed source files only.",
                                              "findings": [], "reviewed_files": ["file.py"]}))
                self.assertEqual(verdict, import_review(output, mode)["verdict"])

    def test_completed_source_review_can_report_an_unperformed_dynamic_review(self):
        for summary in ("A dynamic review could not be performed; inspected source only.",
                        "Couldn't perform the review against the running service; inspected source only.",
                        "Unable to perform a review of production traffic; source review completed."):
            with self.subTest(summary=summary), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "review.json"
                output.write_text(json.dumps({"verdict": "pass", "summary": summary,
                                              "reviewed_files": ["file.py"], "findings": []}))
                self.assertEqual("pass", import_review(output, "post_fix")["verdict"])

    def test_manual_review_import_uses_the_same_output_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.json"
            output.write_text(json.dumps({"reviewed_files": ["src/index.ts"], "verdict": "reviewed", "summary": "x" * (9 * 1024 * 1024), "findings": []}))
            with self.assertRaisesRegex(RuntimeError, "limit"):
                import_review(output, "initial")

    def test_unreadable_manual_review_is_a_typed_tool_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.json"
            for content in (None, "not JSON", "[]"):
                with self.subTest(content=content):
                    if content is not None:
                        output.write_text(content)
                    with self.assertRaises(RuntimeError):
                        import_review(output, "initial")

    def scan_payload(self, dead, rules=None):
        def run(repo, directory, name, arguments):
            data = dead if name == "dead-code" else {"rules": rules or {}} if name == "config" else {}
            return {"status": "completed", "exit_code": 0, "data": data}
        with patch("hangover.oracles._run_fallow", side_effect=run), patch(
            "hangover.oracles.fallow_version", return_value="fallow 3.31.0"
        ):
            return run_fallow_scan(Path("/repo"), Path("/run"), {"javascript": True})

    def test_supported_summary_counts_cannot_hide_missing_findings(self) -> None:
        for field in DEAD_CODE_FIELDS:
            with self.subTest(field=field):
                result = self.scan_payload({"summary": {field: 3}, field: []})
                self.assertEqual("partial", result["status"])
                self.assertEqual("inconsistent", result["commands"]["dead_code"]["status"])
                self.assertIn(field, result["commands"]["dead_code"]["error"])

    def test_malformed_or_mismatched_counts_are_not_complete_evidence(self) -> None:
        for dead in (
            {"summary": {"unused_files": 1}},
            {"summary": {"unused_files": 0}, "unused_files": [{"path": "dead.ts"}]},
            {"summary": {"unused_files": 1}, "unused_files": ["dead.ts"]},
            {"summary": {"unused_files": True}, "unused_files": [{"path": "dead.ts"}]},
            {"summary": {"unused_files": -1}, "unused_files": []},
        ):
            with self.subTest(dead=dead):
                self.assertEqual("partial", self.scan_payload(dead)["status"])

    def test_consistency_check_respects_disabled_rules_and_valid_sparse_payloads(self) -> None:
        for dead, rules in (
            ({"summary": {"unused_dependencies": 3}, "unused_dependencies": []}, {"unused-dependencies": "off"}),
            ({"summary": {"unused_files": 1}, "unused_files": [{"path": "dead.ts"}]}, {}),
            ({"summary": {"unused_files": 0}}, {}),
            ({"unused_files": [{"path": "dead.ts"}]}, {}),
        ):
            with self.subTest(dead=dead, rules=rules):
                self.assertEqual("completed", self.scan_payload(dead, rules)["status"])

    def test_inconsistent_scan_cannot_make_a_missing_finding_stale(self) -> None:
        state = new_state(Path("/repo"))
        initial = self.scan_payload({"unused_dependencies": [{"name": "unused"}]})
        identifier = merge_findings(state, extract_fallow_findings(initial), "before")["ids"][0]
        incomplete = self.scan_payload({"summary": {"unused_dependencies": 1}, "unused_dependencies": []})
        merge_findings(state, extract_fallow_findings(incomplete), "after",
                       scan_result={"kind": "scan", "fallow": incomplete})
        self.assertEqual("open", state["issues"][identifier]["status"])

    def test_unidentified_legacy_note_requires_new_verification(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "hangover verify"):
            validate_note_assessments(
                {"verdict": "pass", "declared_changes_assessed": []},
                [{"at": "legacy", "text": "Unidentified legacy claim"}],
            )

    def test_failed_review_can_report_a_blocker_before_assessing_every_note(self) -> None:
        self.assertIsNone(validate_note_assessments(
            {"verdict": "fail", "declared_changes_assessed": []},
            [{"id": "note-a", "text": "Implementer claim"}],
        ))

    def test_audit_refuses_error_or_missing_verdict(self) -> None:
        for data in (
            {"error": True}, {"error": True, "verdict": "pass"}, {},
            {"verdict": "unknown"}, {"verdict": {"pass": True}},
        ):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result = {"status": "completed", "exit_code": 0, "data": data}
                with patch("hangover.oracles._run_fallow", return_value=result), patch(
                    "hangover.oracles.fallow_version", return_value="fallow 3.31.0"
                ):
                    audit = run_fallow_audit(root, root, "HEAD")
                self.assertNotEqual("completed", audit["status"])

    def test_audit_preserves_supported_verdicts(self) -> None:
        for verdict in ("pass", "warn", "fail"):
            with self.subTest(verdict=verdict), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result = {"status": "completed", "exit_code": 0, "data": {"verdict": verdict}}
                with patch("hangover.oracles._run_fallow", return_value=result), patch(
                    "hangover.oracles.fallow_version", return_value="fallow 3.31.0"
                ):
                    audit = run_fallow_audit(root, root, "HEAD")
                self.assertEqual("completed", audit["status"])
                self.assertEqual(verdict, audit["verdict"])

    def test_dead_code_rule_names_match_fallow_registry(self) -> None:
        self.assertEqual("unused-exports", DEAD_CODE_RULE_BY_FIELD["unused_exports"])
        self.assertEqual("private-type-leaks", DEAD_CODE_RULE_BY_FIELD["private_type_leaks"])
        self.assertEqual("re-export-cycle", DEAD_CODE_RULE_BY_FIELD["re_export_cycles"])

    def test_dead_code_mode_comes_from_type_aware_metadata(self) -> None:
        self.assertEqual(
            "type-aware",
            fallow_dead_code_mode(
                {"data": {"_meta": {"type_aware": {"identity": {"mode": "type-aware"}}}}}
            ),
        )

    def test_dead_code_mode_fallback_is_syntactic(self) -> None:
        self.assertEqual(
            "syntactic",
            fallow_dead_code_mode({"fallback": "type_aware_failed"}),
        )

    def test_legacy_snapshot_infers_dead_code_mode_from_raw_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "dead-code.json"
            raw.write_text(
                json.dumps(
                    {"_meta": {"type_aware": {"identity": {"mode": "type-aware"}}}}
                )
            )
            fallow = {"commands": {"dead_code": {"raw": str(raw)}}}

            self.assertEqual("type-aware", fallow_dead_code_mode(fallow))

    def test_legacy_snapshot_without_mode_markers_defaults_to_syntactic(self) -> None:
        self.assertEqual(
            "syntactic",
            fallow_dead_code_mode({"commands": {"dead_code": {"data": {}}}}),
        )

    def test_fresh_review_uses_general_read_only_exec_with_custom_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q", repo], check=True)
            with patch("hangover.oracles.codex_binary", return_value=Path("/usr/bin/codex")):
                command = codex_review_command(
                    repo, repo / "review.json", repo / "review-home", workspace=repo.parent / "isolated-review"
                )

        self.assertEqual(["/usr/bin/codex", "exec"], command[:2])
        self.assertIn("read-only", command)
        self.assertIn("--ignore-user-config", command)
        self.assertIn("shell_environment_policy.inherit=none", command)
        self.assertTrue(
            any(value.startswith("shell_environment_policy.set.HOME=") for value in command)
        )
        self.assertTrue(
            any(value.startswith("shell_environment_policy.set.ZDOTDIR=") for value in command)
        )
        self.assertEqual(str(repo), command[command.index("--add-dir") + 1])
        self.assertEqual(str(repo.parent / "isolated-review"), command[command.index("-C") + 1])
        self.assertIn("project_doc_max_bytes=0", command)
        self.assertEqual(str((TOOL_ROOT / "schemas/review.schema.json").resolve()),
                         command[command.index("--output-schema") + 1])
        self.assertIn("--skip-git-repo-check", command)
        self.assertEqual("-", command[-1])
        self.assertNotIn("--uncommitted", command)
        self.assertNotIn("review", command[:3])

    def test_delegate_review_command_uses_schema_for_schema_capable_lane(self) -> None:
        with patch("hangover.oracles.delegate_binary", return_value=Path("/usr/bin/delegate")):
            command = delegate_review_command(
                Path("/run/prompt.md"),
                Path("/schemas/review.schema.json"),
                timeout=45,
                lane="codex",
                model="sol",
                reasoning_effort="high",
            )

        self.assertEqual(
            [
                "/usr/bin/delegate",
                "--json",
                "codex",
                "safe",
                "--model",
                "sol",
                "--reasoning-effort",
                "high",
                "--output-schema",
                "/schemas/review.schema.json",
                "--prompt-file",
                "/run/prompt.md",
                "--timeout",
                "45",
            ],
            command,
        )

    def test_delegate_review_command_omits_schema_for_non_schema_lane(self) -> None:
        with patch("hangover.oracles.delegate_binary", return_value=Path("/usr/bin/delegate")):
            command = delegate_review_command(
                Path("/run/prompt.md"),
                Path("/schemas/review.schema.json"),
                lane="glm",
            )

        self.assertNotIn("--output-schema", command)
        self.assertEqual("glm", command[2])
        self.assertEqual(["--prompt-file", "/run/prompt.md"], command[4:6])

    def test_command_template_replaces_only_whole_placeholder_arguments(self) -> None:
        command = substitute_command_template(
            [
                "reviewer",
                "{prompt}",
                "prefix-{prompt}",
                "{output}",
                "{repo}",
                "{schema}",
            ],
            repo=Path("/repo"),
            prompt_path=Path("/run/prompt.md"),
            output_path=Path("/run/review.json"),
            schema_path=Path("/schemas/review.schema.json"),
        )

        self.assertEqual(
            [
                "reviewer",
                "/run/prompt.md",
                "prefix-{prompt}",
                "/run/review.json",
                "/repo",
                "/schemas/review.schema.json",
            ],
            command,
        )

    def test_delegate_review_parser_uses_last_complete_codex_object(self) -> None:
        review = parse_delegate_review(CODEX_ASSISTANT_TEXT, "initial")

        self.assertEqual("reviewed", review["verdict"])
        self.assertIn("three scoped", review["summary"])
        self.assertEqual("dead_code", review["findings"][0]["category"])

    def test_delegate_review_parser_accepts_glm_json_with_trailing_report(self) -> None:
        review = parse_delegate_review(GLM_ASSISTANT_TEXT, "initial")

        self.assertEqual("reviewed", review["verdict"])
        self.assertEqual("duplication", review["findings"][0]["category"])

    def test_delegate_review_parser_rejects_a_truncated_trailing_object(self) -> None:
        for name, text in (
            ("unterminated string", TRUNCATED_STRING_ASSISTANT_TEXT),
            ("unterminated object", TRUNCATED_OBJECT_ASSISTANT_TEXT),
        ):
            with self.subTest(truncation=name):
                with self.assertRaisesRegex(RuntimeError, "truncated"):
                    parse_delegate_review(text, "initial")

    def test_delegate_review_parser_validates_the_last_complete_object(self) -> None:
        stub = '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"planning","findings":[]}'
        trailing = '{"reviewed_files":["src/index.ts"],"verdict":"invalid","summary":"bad","findings":[]}'

        with self.assertRaisesRegex(RuntimeError, "verdict"):
            parse_delegate_review(f"{stub}\n{trailing}", "initial")

    def test_delegate_review_persists_envelope_and_embeds_schema_for_glm(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            repo.mkdir()
            prompt = run_dir / "review-prompt.md"
            prompt.parent.mkdir()
            packet = root / "packet.json"
            packet_text = '{"marker":"packet is inline"}\n'
            packet.write_text(packet_text)
            prompt.write_text(f"Review the packet.\n\nReview packet: {packet}\n")
            envelope = json.dumps(
                {
                    "exitCode": 0,
                    "assistantText": GLM_ASSISTANT_TEXT,
                    "assistantTextTruncated": False,
                }
            )
            completed = subprocess.CompletedProcess([], 0, envelope, "delegate stderr")
            with patch("hangover.oracles.delegate_binary", return_value=Path("/usr/bin/delegate")), patch(
                "hangover.oracles.run_logged", side_effect=logged_result(completed)
            ) as run:
                result = run_delegate_review(
                    repo,
                    run_dir,
                    packet,
                    "initial",
                    lane="glm",
                )

            self.assertEqual("completed", result["status"])
            self.assertEqual("reviewed", json.loads((run_dir / "review.json").read_text())["verdict"])
            self.assertEqual(envelope, (run_dir / "review.stdout").read_text())
            self.assertEqual("delegate stderr", (run_dir / "review.stderr").read_text())
            embedded = (run_dir / "delegate-review-prompt.md").read_text()
            self.assertIn(packet_text.strip(), embedded)
            self.assertIn("packet is inline", embedded)
            self.assertNotIn(f"Review packet: {packet}", embedded)
            self.assertIn("not readable from this context", embedded)
            self.assertIn('"$schema": "https://json-schema.org/draft/2020-12/schema"', embedded)
            self.assertIn("exactly one raw JSON object", embedded)
            kwargs = run.call_args.kwargs
            self.assertIsInstance(run.call_args.args[0], list)
            self.assertEqual(repo, kwargs["cwd"])
            self.assertEqual(1215, kwargs["timeout_seconds"])
            self.assertEqual(git_safe_environment(), kwargs["env"])
            self.assertNotIn("shell", kwargs)

    def test_delegate_claude_schema_omits_only_dialect_without_changing_source(self) -> None:
        canonical = TOOL_ROOT / "schemas" / "review.schema.json"
        original = canonical.read_bytes()
        for lane in ("claude", "codex"):
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                packet = root / "packet.json"
                packet.write_text('{}')

                def reviewer(command, **kwargs):
                    schema_path = Path(command[command.index("--output-schema") + 1])
                    schema = json.loads(schema_path.read_text())
                    expected = json.loads(original)
                    if lane == "claude":
                        expected.pop("$schema")
                    else:
                        self.assertEqual(canonical, schema_path)
                    self.assertEqual(expected, schema)
                    if lane == "claude":
                        self.assertEqual(root, schema_path.parent)
                    return subprocess.CompletedProcess(command, 0, json.dumps({
                        "exitCode": 0,
                        "assistantText": '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"done","findings":[]}',
                    }), "")

                with patch("hangover.oracles.delegate_binary", return_value=Path("/usr/bin/delegate")), patch(
                    "hangover.oracles.run_logged", side_effect=logged_result(reviewer)
                ):
                    result = run_delegate_review(
                        root, root, packet, "initial", lane=lane, prompt_text="Review."
                    )
                self.assertEqual("completed", result["status"])
                self.assertEqual(original, canonical.read_bytes())

    def test_delegate_review_passes_named_parent_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            repo.mkdir()
            prompt = run_dir / "review-prompt.md"
            prompt.parent.mkdir()
            prompt.write_text("Review the packet.")
            packet = root / "packet.json"
            packet.write_text('{"marker":"packet"}\n')
            envelope = json.dumps(
                {
                    "exitCode": 0,
                    "assistantText": json.dumps(
                        {"reviewed_files": ["src/index.ts"], "verdict": "reviewed", "summary": "done", "findings": []}
                    ),
                    "assistantTextTruncated": False,
                }
            )
            completed = subprocess.CompletedProcess([], 0, envelope, "")
            with patch.dict(
                "os.environ",
                {"REVIEW_PROFILE": "selected", "REVIEW_PROXY": "http://proxy.invalid"},
                clear=False,
            ), patch(
                "hangover.oracles.delegate_binary", return_value=Path("/usr/bin/delegate")
            ), patch("hangover.oracles.run_logged", side_effect=logged_result(completed)) as run:
                result = run_delegate_review(
                    repo,
                    run_dir,
                    packet,
                    "initial",
                    lane="glm",
                    env=["REVIEW_PROFILE", "REVIEW_PROXY", "REVIEW_MISSING"],
                )

            self.assertEqual("completed", result["status"])
            expected = git_safe_environment()
            expected.update(
                {"REVIEW_PROFILE": "selected", "REVIEW_PROXY": "http://proxy.invalid"}
            )
            self.assertEqual(expected, run.call_args.kwargs["env"])

    def test_command_review_passes_named_parent_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            repo.mkdir()
            prompt = run_dir / "review-prompt.md"
            prompt.parent.mkdir()
            prompt.write_text("Review the packet.")
            completed = subprocess.CompletedProcess(
                [], 0, json.dumps({"reviewed_files": ["src/index.ts"], "verdict": "reviewed", "summary": "done", "findings": []}), ""
            )
            with patch.dict("os.environ", {"REVIEW_PROFILE": "selected"}, clear=False), patch(
                "hangover.oracles.run_logged", side_effect=logged_result(completed)
            ) as run:
                result = run_command_review(
                    repo,
                    run_dir,
                    root / "packet.json",
                    "initial",
                    ["reviewer"],
                    env=["REVIEW_PROFILE", "REVIEW_MISSING"],
                )

            self.assertEqual("completed", result["status"])
            expected = git_safe_environment()
            expected["REVIEW_PROFILE"] = "selected"
            self.assertEqual(expected, run.call_args.kwargs["env"])

    def test_codex_review_keeps_safe_environment_without_named_passthrough(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            repo.mkdir()
            run_dir.mkdir()
            (run_dir / "review-prompt.md").write_text("Review the packet.")
            (run_dir / "review.json").write_text(
                '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"done","findings":[]}\n'
            )
            completed = subprocess.CompletedProcess([], 0, "", "")
            with patch.dict("os.environ", {"REVIEW_PROFILE": "selected"}, clear=False), patch(
                "hangover.oracles.codex_binary", return_value=Path("/usr/bin/codex")
            ), patch("hangover.oracles.run_logged", side_effect=logged_result(completed)) as run:
                result = run_codex_review(repo, run_dir, root / "packet.json", "initial")

            self.assertEqual("completed", result["status"])
            self.assertEqual(git_safe_environment(), run.call_args.kwargs["env"])

    def test_delegate_review_inlines_post_fix_patches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            repo.mkdir()
            prompt = run_dir / "review-prompt.md"
            prompt.parent.mkdir()
            prompt.write_text("Review the packet.")
            before = root / "before.patch"
            after = root / "after.patch"
            before_text = "--- before\n+++ before\n-old\n+new\n"
            after_text = "--- after\n+++ after\n-old\n+newer"
            before.write_text(before_text)
            after.write_text(after_text)
            packet = root / "packet.json"
            packet_text = json.dumps(
                {
                    "mode": "post_fix",
                    "before_patch": str(before),
                    "after_patch": str(after),
                }
            ) + "\n"
            packet.write_text(packet_text)
            envelope = json.dumps(
                {
                    "exitCode": 0,
                    "assistantText": json.dumps(
                        {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "done", "findings": []}
                    ),
                    "assistantTextTruncated": False,
                }
            )
            completed = subprocess.CompletedProcess([], 0, envelope, "")
            with patch("hangover.oracles.delegate_binary", return_value=Path("/usr/bin/delegate")), patch(
                "hangover.oracles.run_logged", side_effect=logged_result(completed)
            ):
                result = run_delegate_review(
                    repo,
                    run_dir,
                    packet,
                    "post_fix",
                    lane="glm",
                )

            self.assertEqual("completed", result["status"])
            embedded = (run_dir / "delegate-review-prompt.md").read_text()
            self.assertIn(packet_text.strip(), embedded)
            self.assertIn(before_text, embedded)
            self.assertIn(f"{after_text}\n```", embedded)

    def test_delegate_envelope_sharp_edges_have_distinct_statuses(self) -> None:
        cases = (
            (
                {
                    "exitCode": 0,
                    "assistantText": GLM_ASSISTANT_TEXT,
                    "assistantTextTruncated": True,
                },
                "failed",
            ),
            (
                {
                    "exitCode": 7,
                    "assistantText": GLM_ASSISTANT_TEXT,
                    "assistantTextTruncated": False,
                },
                "failed",
            ),
            (
                {
                    "exitCode": 0,
                    "assistantText": (
                        '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"planning","findings":[]}\n'
                        '{"reviewed_files":["src/index.ts"],"verdict":"invalid","summary":"bad","findings":[]}'
                    ),
                    "assistantTextTruncated": False,
                },
                "invalid_output",
            ),
            (
                {
                    "exitCode": 0,
                    "assistantText": TRUNCATED_STRING_ASSISTANT_TEXT,
                    "assistantTextTruncated": False,
                },
                "invalid_output",
            ),
            (
                {
                    "exitCode": 0,
                    "assistantText": TRUNCATED_OBJECT_ASSISTANT_TEXT,
                    "assistantTextTruncated": False,
                },
                "invalid_output",
            ),
            ([], "invalid_output"),
            (
                {"exitCode": 0, "assistantText": [], "assistantTextTruncated": False},
                "invalid_output",
            ),
        )
        for envelope_value, expected_status in cases:
            with self.subTest(envelope=envelope_value):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    repo = root / "repo"
                    run_dir = root / "run"
                    repo.mkdir()
                    run_dir.mkdir()
                    (run_dir / "review-prompt.md").write_text("Review the packet.")
                    packet = root / "packet.json"
                    packet.write_text('{"marker":"packet"}\n')
                    envelope = json.dumps(envelope_value)
                    completed = subprocess.CompletedProcess([], 0, envelope, "")
                    with patch("hangover.oracles.delegate_binary", return_value=Path("/usr/bin/delegate")), patch(
                        "hangover.oracles.run_logged", side_effect=logged_result(completed)
                    ) as run:
                        result = run_delegate_review(
                            repo,
                            run_dir,
                            packet,
                            "initial",
                            timeout=37,
                            lane="glm",
                        )

                    self.assertEqual(expected_status, result["status"])
                    self.assertEqual(1, run.call_count)
                    self.assertEqual(
                        [
                            "/usr/bin/delegate",
                            "--json",
                            "glm",
                            "safe",
                            "--prompt-file",
                            str(run_dir / "delegate-review-prompt.md"),
                            "--timeout",
                            "37",
                        ],
                        run.call_args.args[0],
                    )
                    self.assertEqual(repo, run.call_args.kwargs["cwd"])
                    self.assertEqual(52, run.call_args.kwargs["timeout_seconds"])
                    self.assertEqual(git_safe_environment(), run.call_args.kwargs["env"])
                    self.assertNotIn("shell", run.call_args.kwargs)

    def test_delegate_binary_honors_exact_environment_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "delegate"
            binary.write_text("#!/bin/sh\n")
            binary.chmod(0o755)
            with patch.dict("os.environ", {"HANGOVER_DELEGATE_BIN": str(binary)}):
                self.assertEqual(binary.resolve(), delegate_binary())

    def test_invalid_delegate_override_does_not_fall_back_to_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path_binary = root / "delegate"
            path_binary.write_text("#!/bin/sh\n")
            path_binary.chmod(0o755)
            with patch.dict(
                "os.environ",
                {
                    "HANGOVER_DELEGATE_BIN": str(root / "missing-delegate"),
                    "PATH": str(root),
                },
            ):
                self.assertIsNone(delegate_binary())

    def test_command_review_parses_stdout_and_sends_stdin_without_prompt_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            repo.mkdir()
            prompt = run_dir / "review-prompt.md"
            prompt.parent.mkdir()
            prompt.write_text("Review the packet.")
            completed = subprocess.CompletedProcess(
                [], 0, json.dumps({"reviewed_files": ["src/index.ts"], "verdict": "reviewed", "summary": "done", "findings": []}), ""
            )
            with patch("hangover.oracles.run_logged", side_effect=logged_result(completed)) as run:
                result = run_command_review(
                    repo,
                    run_dir,
                    root / "packet.json",
                    "initial",
                    ["reviewer", "prefix-{output}"],
                )

            self.assertEqual("completed", result["status"])
            self.assertTrue((run_dir / "review.json").is_file())
            self.assertEqual("reviewed", json.loads((run_dir / "review.json").read_text())["verdict"])
            self.assertEqual(repo, Path(run.call_args.kwargs["cwd"]))
            self.assertEqual("Review the packet.", run.call_args.kwargs["input_text"])
            self.assertIsInstance(run.call_args.args[0], list)
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_command_review_uses_prompt_file_without_stdin_when_placeholder_is_present(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            repo.mkdir()
            prompt = run_dir / "review-prompt.md"
            prompt.parent.mkdir()
            prompt.write_text("Review the packet.")
            completed = subprocess.CompletedProcess(
                [], 0, json.dumps({"reviewed_files": ["src/index.ts"], "verdict": "reviewed", "summary": "done", "findings": []}), ""
            )
            with patch("hangover.oracles.run_logged", side_effect=logged_result(completed)) as run:
                result = run_command_review(
                    repo,
                    run_dir,
                    root / "packet.json",
                    "initial",
                    ["reviewer", "{prompt}"],
                )

            self.assertEqual("completed", result["status"])
            self.assertEqual(str(prompt), run.call_args.args[0][1])
            self.assertIsNone(run.call_args.kwargs["input_text"])
            self.assertIsInstance(run.call_args.args[0], list)
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_command_review_reads_output_file_when_output_placeholder_is_used(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            repo.mkdir()
            prompt = run_dir / "review-prompt.md"
            prompt.parent.mkdir()
            prompt.write_text("Review the packet.")
            output = run_dir / "review.json"
            output.write_text('{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"done","findings":[]}\n')
            completed = subprocess.CompletedProcess([], 0, "stdout is ignored", "")
            with patch("hangover.oracles.run_logged", side_effect=logged_result(completed)) as run:
                result = run_command_review(
                    repo,
                    run_dir,
                    root / "packet.json",
                    "initial",
                    ["reviewer", "{output}"],
                )

            self.assertEqual("completed", result["status"])
            self.assertEqual("reviewed", json.loads(output.read_text())["verdict"])
            self.assertIsInstance(run.call_args.args[0], list)
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_import_rejects_incomplete_finding_before_backlog_merge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.json"
            output.write_text(
                '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"done","findings":[{}]}\n'
            )
            with self.assertRaisesRegex(RuntimeError, "missing"):
                import_review(output, "initial")

    def test_import_enforces_schema_enums(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.json"
            output.write_text(
                '{\n  "reviewed_files":["src/index.ts"],"verdict": "reviewed",\n  "summary": "done",\n  "findings": [{\n    "category": "dead_code", "title": "item", "evidence": ["evidence"],\n    "files": ["src/item.ts"], "symbols": [], "harm": "harm",\n    "proposed_change": "delete", "invariants": ["behavior"],\n    "risk": "low", "priority": "P9", "confidence": "high",\n    "verification": ["test"], "chesterton": "known"\n  }]\n}\n'
            )
            with self.assertRaisesRegex(RuntimeError, "priority is invalid"):
                import_review(output, "initial")

    def test_passing_review_cannot_reject_a_declared_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.json"
            output.write_text(json.dumps({"reviewed_files": ["src/index.ts"], 
                "verdict": "pass", "summary": "contradictory", "findings": [],
                "declared_changes_assessed": [{
                    "note": "Change public behavior", "verdict": "rejected",
                    "evidence": ["The change violates a behavioral invariant."],
                }],
            }))

            with self.assertRaisesRegex(RuntimeError, "passing.*rejected"):
                import_review(output, "post_fix")

    def test_import_accepts_declared_change_assessment_and_existing_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.json"
            output.write_text(json.dumps({"reviewed_files": ["src/index.ts"], 
                "verdict": "pass", "summary": "supported", "findings": [],
                "declared_changes_assessed": [{
                    "note": "Shared hook intentionally handles tall figures.",
                    "verdict": "accepted",
                    "evidence": ["History and focused tests support the threshold behavior."],
                }],
            }))
            review = import_review(output, "post_fix")
            self.assertEqual("accepted", review["declared_changes_assessed"][0]["verdict"])
            output.write_text('{"reviewed_files":["src/index.ts"],"verdict":"pass","summary":"legacy","findings":[]}')
            self.assertEqual("pass", import_review(output, "post_fix")["verdict"])

    def test_import_rejects_fields_that_could_override_internal_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.json"
            output.write_text(
                '{\n  "reviewed_files":["src/index.ts"],"verdict": "reviewed",\n  "summary": "done",\n  "findings": [{\n    "category": "dead_code", "title": "item", "evidence": ["evidence"],\n    "files": ["src/item.ts"], "symbols": [], "harm": "harm",\n    "proposed_change": "delete", "invariants": ["behavior"],\n    "risk": "low", "priority": "P2", "confidence": "high",\n    "verification": ["test"], "chesterton": "known",\n    "source": "fallow"\n  }]\n}\n'
            )
            with self.assertRaisesRegex(RuntimeError, "unsupported fields: source"):
                import_review(output, "initial")

    def test_post_fix_pass_cannot_hide_a_blocking_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.json"
            output.write_text(
                '{\n  "reviewed_files":["src/index.ts"],"verdict": "pass",\n  "summary": "done",\n  "findings": [{\n    "category": "behavior_regression", "title": "broken", "evidence": ["evidence"],\n    "files": ["src/item.ts"], "symbols": [], "harm": "harm",\n    "proposed_change": "fix", "invariants": ["behavior"],\n    "risk": "high", "priority": "P1", "confidence": "high",\n    "verification": ["test"], "chesterton": "known"\n  }]\n}\n'
            )
            with self.assertRaisesRegex(RuntimeError, "cannot include a P0 or P1"):
                import_review(output, "post_fix")

    def test_post_review_fingerprint_is_scoped_to_its_parent_issue(self) -> None:
        item = {
            "category": "test_regression",
            "title": "Stale output remains",
            "evidence": ["evidence"],
            "files": ["dist/stale.js"],
            "symbols": [],
            "harm": "harm",
            "proposed_change": "fix",
            "invariants": ["behavior"],
            "risk": "medium",
            "priority": "P1",
            "confidence": "high",
            "verification": ["verify"],
            "chesterton": "reason",
        }
        review = {"findings": [item]}

        first = review_findings(review, "post-review", "issue-a")[0]["fingerprint"]
        second = review_findings(review, "post-review", "issue-b")[0]["fingerprint"]

        self.assertNotEqual(first, second)

    def test_current_fallow_route_categories_are_not_silently_dropped(self) -> None:
        result = {
            "commands": {
                "dead_code": {
                    "data": {
                        "summary": {"route_collisions": 1},
                        "route_collisions": [{"path": "app/page.tsx"}],
                    }
                }
            },
            "dependency_analysis": "complete",
        }

        findings = extract_fallow_findings(result)

        self.assertEqual("route_collisions", findings[0]["category"])

    def test_add_to_config_action_becomes_a_suppression_recipe(self) -> None:
        result = {
            "commands": {
                "dead_code": {
                    "data": {
                        "summary": {"dev_dependencies_in_production": 1},
                        "dev_dependencies_in_production": [
                            {
                                "package_name": "chrome-launcher",
                                "path": "package.json",
                                "actions": [
                                    {"type": "move-to-prod", "auto_fixable": False},
                                    {
                                        "type": "add-to-config",
                                        "auto_fixable": False,
                                        "config_key": "ignoreDependencies",
                                        "value": "chrome-launcher",
                                    },
                                ],
                            }
                        ],
                    }
                }
            },
            "dependency_analysis": "complete",
        }

        findings = extract_fallow_findings(result)

        self.assertEqual(
            {"config_key": "ignoreDependencies", "value": "chrome-launcher"},
            findings[0]["suppression"],
        )

    def test_unknown_nonzero_fallow_category_becomes_visible_backlog_evidence(self) -> None:
        result = {
            "commands": {
                "dead_code": {
                    "data": {
                        "summary": {"future_category": 1},
                        "future_category": [{"path": "src/future.ts"}],
                    }
                }
            },
            "dependency_analysis": "complete",
        }

        findings = extract_fallow_findings(result)

        self.assertEqual("fallow_unmapped", findings[0]["category"])
        self.assertEqual(["src/future.ts"], findings[0]["files"])

    def test_same_file_duplication_title_uses_instance_count_and_suggested_name(self) -> None:
        result = {
            "commands": {
                "dupes": {
                    "data": {
                        "clone_groups": [
                            {
                                "instances": [
                                    {"file": "app/api/edition/route.ts", "start_line": 10},
                                    {"file": "app/api/edition/route.ts", "start_line": 40},
                                ],
                                "line_count": 9,
                                "token_count": 56,
                                "fingerprint": "dup:8e09948e",
                                "suggested_name": "contentLength",
                            }
                        ]
                    }
                }
            }
        }

        finding = extract_fallow_findings(result)[0]

        self.assertEqual(
            "Consolidate 9 duplicated lines repeated twice within app/api/edition/route.ts",
            finding["title"],
        )
        self.assertEqual(
            ["fallow", "duplication", "dup:8e09948e"], finding["fingerprint"]
        )
        self.assertEqual(["contentLength"], finding["symbols"])
        evidence = " ".join(finding["evidence"])
        self.assertIn("app/api/edition/route.ts", evidence)
        self.assertIn("2 instances", evidence)
        self.assertIn("56 tokens", evidence)
        self.assertIn("Fallow suggests extracting `contentLength`", evidence)

    def test_duplication_evidence_has_ranges_fragments_and_stable_fingerprint(self) -> None:
        base_group = {
            "instances": [
                {"file": "a.ts", "start_line": 10, "end_line": 14,
                 "fragment": "one\ntwo\nthree\nfour"},
                {"file": "b.ts", "start_line": 20, "end_line": 24},
            ],
            "line_count": 5, "token_count": 20, "fingerprint": "dup:stable",
        }
        payload = {"commands": {"dupes": {"data": {"clone_groups": [base_group]}}}}
        upgraded = extract_fallow_findings(payload)[0]
        legacy = extract_fallow_findings({"commands": {"dupes": {"data": {
            "clone_groups": [{**base_group, "instances": [
                {"file": "a.ts"}, {"file": "b.ts"}
            ]}]
        }}}})[0]
        self.assertEqual(legacy["fingerprint"], upgraded["fingerprint"])
        self.assertIn("Instance: a.ts:10-14", upgraded["evidence"])
        self.assertIn("Fragment at a.ts:10-14:\none\ntwo\nthree", upgraded["evidence"])

    def test_two_file_duplication_title_names_both_files(self) -> None:
        result = {
            "commands": {
                "dupes": {
                    "data": {
                        "clone_groups": [
                            {
                                "instances": [
                                    {"file": "app/api/edition/route.ts"},
                                    {"file": "app/api/subscribe/route.ts"},
                                ],
                                "line_count": 9,
                                "token_count": 56,
                                "fingerprint": "dup:two-files",
                            }
                        ]
                    }
                }
            }
        }

        finding = extract_fallow_findings(result)[0]

        self.assertEqual(
            "Consolidate 9 duplicated lines shared by app/api/edition/route.ts and app/api/subscribe/route.ts",
            finding["title"],
        )

    def test_four_file_duplication_title_lists_three_then_remainder(self) -> None:
        result = {
            "commands": {
                "dupes": {
                    "data": {
                        "clone_groups": [
                            {
                                "instances": [
                                    {"file": "d.ts"},
                                    {"file": "b.ts"},
                                    {"file": "a.ts"},
                                    {"file": "c.ts"},
                                ],
                                "line_count": 9,
                                "token_count": 56,
                                "fingerprint": "dup:four-files",
                            }
                        ]
                    }
                }
            }
        }

        finding = extract_fallow_findings(result)[0]

        self.assertEqual(
            "Consolidate 9 duplicated lines shared by 4 files (a.ts, b.ts, c.ts, +1 more)",
            finding["title"],
        )
        self.assertEqual(["a.ts", "b.ts", "c.ts", "d.ts"], finding["files"])

    def test_feature_flag_occurrences_are_grouped_by_name(self) -> None:
        result = {
            "commands": {
                "flags": {
                    "data": {
                        "feature_flags": [
                            {
                                "flag_name": "NEXT_PUBLIC_ENABLE_NEWSLETTER",
                                "path": "test/subscribe-route.test.ts",
                                "line": 18,
                            },
                            {
                                "flag_name": "NEXT_PUBLIC_ENABLE_NEWSLETTER",
                                "path": "lib/site-config.ts",
                                "line": 7,
                            },
                        ]
                    }
                }
            }
        }

        findings = extract_fallow_findings(result)

        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual(
            ["fallow", "feature_flag", "NEXT_PUBLIC_ENABLE_NEWSLETTER"],
            finding["fingerprint"],
        )
        self.assertEqual(
            ["lib/site-config.ts", "test/subscribe-route.test.ts"], finding["files"]
        )
        evidence = " ".join(finding["evidence"])
        self.assertIn("lib/site-config.ts:7", evidence)
        self.assertIn("test/subscribe-route.test.ts:18", evidence)

    def test_flag_retirement_reasons_shape_the_flag_card(self) -> None:
        site = {"path": "lib/flags.ts", "line": 3, "col": 6, "role": "read", "in_test": False}
        result = {"commands": {"flags": {"data": {
            "feature_flags": [
                {"flag_name": "ENABLE_A", "path": "lib/a.ts", "line": 4},
                {"flag_name": "ENABLE_B", "path": "lib/b.ts", "line": 9},
            ],
            "retirement": {"flags": [
                {"flag_name": "ENABLE_A", "reasons": ["single-read-site"], "sites": [],
                 "evidence": [{"reason": "single-read-site", "path": "lib/a.ts", "line": 4,
                               "detail": "the flag has one read site"}]},
                {"flag_name": "ENABLE_B", "reasons": [], "sites": [], "evidence": []},
                {"flag_name": "FEATURE_NEW_UI", "kind": "constant", "reasons": ["literal-constant"],
                 "sites": [site], "evidence": [{"reason": "literal-constant", "path": "lib/flags.ts",
                                                "line": 3, "detail": "const FEATURE_NEW_UI = true"}]},
            ]},
        }}}}

        cards = {card["symbols"][0]: card for card in extract_fallow_findings(result)}

        self.assertEqual({"ENABLE_A", "ENABLE_B", "FEATURE_NEW_UI"}, set(cards))
        strong = cards["FEATURE_NEW_UI"]
        self.assertEqual(["fallow", "feature_flag", "FEATURE_NEW_UI"], strong["fingerprint"])
        self.assertEqual("Retire feature flag FEATURE_NEW_UI", strong["title"])
        self.assertEqual(("P2", "medium"), (strong["priority"], strong["confidence"]))
        self.assertEqual(["lib/flags.ts"], strong["files"])
        self.assertTrue(any("const FEATURE_NEW_UI = true" in line for line in strong["evidence"]))
        weak = cards["ENABLE_A"]
        self.assertEqual("Establish whether feature flag ENABLE_A still varies", weak["title"])
        self.assertEqual(("P3", "low"), (weak["priority"], weak["confidence"]))
        self.assertTrue(any("single-read-site" in line for line in weak["evidence"]))
        self.assertFalse(any("retirement candidate" in line for line in cards["ENABLE_B"]["evidence"]))

    def test_flag_retirement_is_strong_only_when_every_workspace_agrees(self) -> None:
        def row(workspace, reasons, line):
            return {"flag_name": "ENABLE_X", "workspace": workspace, "reasons": reasons, "evidence": [],
                    "sites": [{"path": f"{workspace}/flags.ts", "line": line, "role": "read"}]}
        result = {"commands": {"flags": {"data": {"feature_flags": [], "retirement": {"flags": [
            row("apps/a", ["literal-constant"], 1), row("apps/b", [], 2)]}}}}}

        (card,) = extract_fallow_findings(result)

        self.assertEqual("Establish whether feature flag ENABLE_X still varies", card["title"])
        self.assertEqual(["apps/a/flags.ts", "apps/b/flags.ts"], card["files"])
        result["commands"]["flags"]["data"]["retirement"]["flags"][1]["reasons"] = ["empty-branch"]
        (card,) = extract_fallow_findings(result)
        self.assertEqual("Retire feature flag ENABLE_X", card["title"])
        rows = result["commands"]["flags"]["data"]["retirement"]["flags"]
        rows[0]["reasons"], rows[1]["reasons"] = [], ["single-read-site"]
        (card,) = extract_fallow_findings(result)
        self.assertEqual(["apps/a/flags.ts", "apps/b/flags.ts"], card["files"])
        self.assertIn("Fallow's retirement report found ENABLE_X at apps/a/flags.ts:1.", card["evidence"])
        result["commands"]["flags"]["data"]["retirement"]["flags"] = [row("apps/a", [], 1)]
        self.assertEqual([], extract_fallow_findings(result))

    def _complexity_fn(
        self,
        path: str,
        name: str,
        *,
        severity: str = "high",
        exceeded: str = "both",
        **fields: object,
    ) -> dict:
        item = {
            "path": path,
            "name": name,
            "line": 42,
            "col": 0,
            "cyclomatic": 28,
            "cognitive": 22,
            "line_count": 95,
            "param_count": 3,
            "exceeded": exceeded,
            "severity": severity,
        }
        item.update(fields)
        return item

    def _health_scan(
        self,
        findings: list,
        *,
        hotspots: list | None = None,
        summary: dict | None = None,
        vital_signs: dict | None = None,
    ) -> dict:
        data: dict = {
            "summary": summary
            if summary is not None
            else {
                "functions_above_threshold": 1,
                "max_cyclomatic_threshold": 20,
                "max_cognitive_threshold": 15,
            },
            "findings": findings,
        }
        if hotspots is not None:
            data["hotspots"] = hotspots
        if vital_signs is not None:
            data["vital_signs"] = vital_signs
        return {"commands": {"health": {"data": data}}}

    def test_health_complexity_finding_becomes_a_backlog_finding(self) -> None:
        result = self._health_scan(
            [self._complexity_fn("src/parser.ts", "parseExpression")]
        )

        findings = extract_fallow_findings(result)

        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual(
            ["fallow", "complexity", "src/parser.ts", "parseExpression", "ambiguous-v2", None, None, 42, 0, 0],
            finding["fingerprint"],
        )
        self.assertTrue(finding["complexity_identity"]["ambiguous"])
        self.assertEqual("complexity", finding["category"])
        self.assertEqual("fallow", finding["source"])
        self.assertEqual(FALLOW_VERSION, finding["source_version"])
        self.assertEqual(
            "Reduce complexity of parseExpression in src/parser.ts",
            finding["title"],
        )
        self.assertEqual(["src/parser.ts"], finding["files"])
        self.assertEqual(["parseExpression"], finding["symbols"])
        self.assertEqual("medium", finding["risk"])
        self.assertEqual("high", finding["confidence"])
        self.assertEqual("P2", finding["priority"])
        evidence = " ".join(finding["evidence"])
        self.assertIn("parseExpression", evidence)
        self.assertIn("src/parser.ts:42", evidence)
        self.assertIn("cyclomatic 28", evidence)
        self.assertIn("cognitive 22", evidence)
        self.assertIn("20/15", evidence)
        self.assertIn("exceeded: both", evidence)
        self.assertEqual(
            "A function this complex resists safe modification: every branch multiplies the states a maintainer must hold in mind, and defects hide in the interactions.",
            finding["harm"],
        )
        self.assertEqual(
            "Extract coherent sub-steps behind existing seams, flatten nesting with early returns, and split policy from mechanics — without changing any observable behavior.",
            finding["proposed_change"],
        )
        self.assertEqual(
            [
                "Every caller observes identical inputs, outputs, side effects, and error behavior.",
                "No test is weakened or deleted to make the refactor pass.",
            ],
            finding["invariants"],
        )
        self.assertEqual(
            [
                "Run the narrowest tests covering the function, then the repository's configured full gate.",
                "Re-scan and confirm the function's complexity dropped without new findings elsewhere.",
            ],
            finding["verification"],
        )
        self.assertEqual(
            "High complexity sometimes encodes essential domain policy; identify which branches are essential before extracting or collapsing any of them.",
            finding["chesterton"],
        )
        self.assertNotIn("suppression", finding)

    def test_complexity_severity_maps_to_priority(self) -> None:
        result = self._health_scan(
            [
                self._complexity_fn("a.ts", "criticalFn", severity="critical"),
                self._complexity_fn("b.ts", "highFn", severity="high"),
                self._complexity_fn("c.ts", "moderateFn", severity="moderate"),
                self._complexity_fn("d.ts", "unknownFn", severity="mystery"),
            ]
        )

        findings = extract_fallow_findings(result)
        by_name = {item["symbols"][0]: item["priority"] for item in findings}

        self.assertEqual("P1", by_name["criticalFn"])
        self.assertEqual("P2", by_name["highFn"])
        self.assertEqual("P3", by_name["moderateFn"])
        self.assertEqual("P3", by_name["unknownFn"])

    def test_top_tier_hotspot_bumps_priority_and_adds_reason(self) -> None:
        result = self._health_scan(
            [
                self._complexity_fn(
                    "hot.ts", "cognitiveFn", severity="moderate", exceeded="cognitive"
                ),
                self._complexity_fn("cold.ts", "untouchedFn", severity="moderate"),
            ],
            hotspots=[
                {
                    "path": "hot.ts",
                    "score": 92,
                    "commits": 28,
                    "trend": "accelerating",
                },
            ],
            vital_signs={"hotspot_top_pct_count": 1},
        )

        findings = extract_fallow_findings(result)
        by_name = {item["symbols"][0]: item for item in findings}

        bumped = by_name["cognitiveFn"]
        self.assertEqual("P2", bumped["priority"])
        self.assertIn(
            "Priority raised one level: hot.ts is a top-tier Fallow hotspot "
            "(92, 28 commits, trend accelerating).",
            bumped["evidence"],
        )
        self.assertIn(
            "Fallow hotspot score 92 (28 commits, trend accelerating).",
            bumped["evidence"],
        )

        untouched = by_name["untouchedFn"]
        self.assertEqual("P3", untouched["priority"])
        self.assertFalse(
            any("hotspot" in line.lower() or "commits" in line.lower() for line in untouched["evidence"])
        )

    def test_crap_only_estimated_coverage_is_a_low_confidence_p3(self) -> None:
        result = self._health_scan(
            [
                self._complexity_fn(
                    "est.ts",
                    "estimatedFn",
                    exceeded="crap",
                    crap=45.2,
                    coverage_pct=40,
                    coverage_source="estimated",
                ),
                self._complexity_fn(
                    "real.ts",
                    "measuredFn",
                    exceeded="crap",
                    crap=51.0,
                    coverage_pct=12,
                    coverage_source="istanbul",
                ),
            ]
        )

        findings = extract_fallow_findings(result)
        by_name = {item["symbols"][0]: item for item in findings}

        estimated = by_name["estimatedFn"]
        self.assertEqual("P3", estimated["priority"])
        self.assertEqual("low", estimated["confidence"])
        self.assertEqual(
            "CRAP is computed from estimated coverage; wire an Istanbul report into Fallow `health.coverage` for a real score.",
            estimated["evidence"][0],
        )
        estimated_evidence = " ".join(estimated["evidence"])
        self.assertIn("45.2", estimated_evidence)
        self.assertIn("40", estimated_evidence)
        self.assertIn("coverage was estimated", estimated_evidence)

        measured = by_name["measuredFn"]
        self.assertEqual("P2", measured["priority"])
        self.assertEqual("high", measured["confidence"])
        measured_evidence = " ".join(measured["evidence"])
        self.assertIn("51.0", measured_evidence)
        self.assertIn("12", measured_evidence)
        self.assertIn("coverage was measured", measured_evidence)
        self.assertNotIn("coverage was estimated", measured_evidence)

    def test_cognitive_crap_with_estimated_coverage_keeps_metric_priority(self) -> None:
        result = self._health_scan(
            [
                self._complexity_fn(
                    "mixed.ts",
                    "cognitiveFn",
                    severity="critical",
                    exceeded="cognitive_crap",
                    crap=51.0,
                    coverage_pct=12,
                    coverage_source="estimated",
                )
            ]
        )

        finding = extract_fallow_findings(result)[0]

        self.assertEqual("P1", finding["priority"])
        self.assertEqual("high", finding["confidence"])
        self.assertNotIn("wire an Istanbul report", " ".join(finding["evidence"]))

    def test_crap_only_estimated_coverage_top_tier_hotspot_stays_p3(self) -> None:
        result = self._health_scan(
            [
                self._complexity_fn(
                    "hot.ts",
                    "estimatedHotspot",
                    severity="critical",
                    exceeded="crap",
                    crap=75.0,
                    coverage_pct=0,
                    coverage_source="estimated",
                )
            ],
            hotspots=[
                {"path": "hot.ts", "score": 95, "commits": 20, "trend": "stable"}
            ],
            vital_signs={"hotspot_top_pct_count": 1},
        )

        finding = extract_fallow_findings(result)[0]

        self.assertEqual("P3", finding["priority"])
        self.assertEqual("low", finding["confidence"])
        self.assertIn(
            "Fallow hotspot score 95 (20 commits, trend stable).",
            finding["evidence"],
        )
        self.assertFalse(
            any(line.startswith("Priority raised one level:") for line in finding["evidence"])
        )

    def test_non_top_hotspot_does_not_bump_priority(self) -> None:
        result = self._health_scan(
            [self._complexity_fn("ordinary.ts", "moderateFn", severity="moderate")],
            hotspots=[
                {
                    "path": "ranked-first.ts",
                    "score": 20.9,
                    "commits": 19,
                    "trend": "accelerating",
                },
                {
                    "path": "ordinary.ts",
                    "score": 6.9,
                    "commits": 7,
                    "trend": "cooling",
                },
            ],
            vital_signs={"hotspot_top_pct_count": 1},
        )

        finding = extract_fallow_findings(result)[0]

        self.assertEqual("P3", finding["priority"])
        self.assertIn(
            "Fallow hotspot score 6.9 (7 commits, trend cooling).",
            finding["evidence"],
        )
        self.assertFalse(
            any(line.startswith("Priority raised one level:") for line in finding["evidence"])
        )

    def test_cooling_top_tier_hotspot_does_not_bump_priority(self) -> None:
        result = self._health_scan(
            [self._complexity_fn("cooling.ts", "moderateFn", severity="moderate")],
            hotspots=[
                {
                    "path": "cooling.ts",
                    "score": 13.0,
                    "commits": 41,
                    "trend": "cooling",
                }
            ],
            vital_signs={"hotspot_top_pct_count": 1},
        )

        finding = extract_fallow_findings(result)[0]

        self.assertEqual("P3", finding["priority"])
        self.assertIn(
            "Fallow hotspot score 13.0 (41 commits, trend cooling).",
            finding["evidence"],
        )
        self.assertFalse(
            any(line.startswith("Priority raised one level:") for line in finding["evidence"])
        )

    def test_metric_backed_crap_finding_keeps_high_confidence_despite_estimated_coverage(self) -> None:
        result = self._health_scan(
            [
                self._complexity_fn(
                    "mixed.ts",
                    "metricBackedFn",
                    exceeded="cyclomatic_crap",
                    crap=48.0,
                    coverage_pct=None,
                    coverage_source="estimated",
                )
            ]
        )

        findings = extract_fallow_findings(result)

        self.assertEqual("high", findings[0]["confidence"])
        evidence = " ".join(findings[0]["evidence"])
        self.assertIn("coverage unknown", evidence)
        self.assertNotIn("None%", evidence)

    def test_health_add_to_config_action_becomes_a_suppression_recipe(self) -> None:
        result = self._health_scan(
            [
                self._complexity_fn(
                    "src/parser.ts",
                    "parseExpression",
                    actions=[
                        {
                            "type": "refactor-function",
                            "auto_fixable": False,
                            "description": "Extract nested branches into named helpers.",
                        },
                        {
                            "type": "add-to-config",
                            "auto_fixable": False,
                            "config_key": "health.ignoreFunctions",
                            "value": "parseExpression",
                        },
                    ],
                )
            ]
        )

        findings = extract_fallow_findings(result)

        self.assertEqual(
            {"config_key": "health.ignoreFunctions", "value": "parseExpression"},
            findings[0]["suppression"],
        )
        self.assertIn(
            "Extract nested branches into named helpers.",
            findings[0]["evidence"],
        )

    def test_malformed_health_findings_are_skipped(self) -> None:
        result = self._health_scan(
            [
                "not-a-dict",
                {"name": "missingPath", "severity": "high", "cyclomatic": 30},
                {"path": "", "name": "emptyPath", "severity": "high"},
                {"path": 12, "name": "numericPath", "severity": "high"},
                self._complexity_fn("ok.ts", "keepMe", severity="moderate"),
            ]
        )

        findings = extract_fallow_findings(result)

        self.assertEqual(1, len(findings))
        self.assertEqual("keepMe", findings[0]["symbols"][0])

        extract_fallow_findings(self._health_scan(None))
        extract_fallow_findings({"commands": {"health": {"data": {"findings": {}}}}})

    def test_summarize_fallow_surfaces_functions_above_threshold(self) -> None:
        summary = summarize_fallow(
            {
                "health": {
                    "data": {
                        "summary": {"functions_above_threshold": 7},
                        "health_score": {"score": 71, "grade": "C"},
                    }
                }
            }
        )

        self.assertEqual(7, summary["functions_above_threshold"])

        missing = summarize_fallow({"health": {"data": {}}})
        self.assertIsNone(missing["functions_above_threshold"])

    def test_scan_health_command_requests_the_complexity_section(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            repo.mkdir()
            binary = root / "fallow"
            binary.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "--version" ]; then echo "fallow 3.31.0"; else echo "{}"; fi\n'
            )
            binary.chmod(0o755)
            with patch.dict("os.environ", {"HANGOVER_FALLOW_BIN": str(binary)}):
                result = run_fallow_scan(
                    repo,
                    run_dir,
                    {"javascript": True, "typescript": False, "has_node_modules": True},
                )

        health_command = result["commands"]["health"]["command"]
        self.assertIn("--complexity", health_command)
        self.assertIn("--hotspots", health_command)
        # A stale or foreign churn cache silently zeroes or inflates hotspots.
        self.assertIn("--no-cache", health_command)

    def test_scan_selects_dead_code_flags_from_campaign_mode(self) -> None:
        def fake_run(_repo, _run_dir, name, arguments, timeout=600):
            data = {}
            if name == "dead-code" and "--type-aware" in arguments:
                data = {
                    "_meta": {
                        "type_aware": {"identity": {"mode": "type-aware"}}
                    }
                }
            return {"status": "completed", "data": data}

        cases = (
            (None, "--type-aware", "--no-type-aware"),
            ("syntactic", "--no-type-aware", "--type-aware"),
            ("type-aware", "--type-aware", "--no-type-aware"),
        )
        for mode, expected, rejected in cases:
            with self.subTest(mode=mode), patch(
                "hangover.oracles._run_fallow", side_effect=fake_run
            ) as run, patch(
                "hangover.oracles.fallow_version", return_value="fallow 3.31.0"
            ):
                run_fallow_scan(
                    Path("/repo"),
                    Path("/run"),
                    {"javascript": True, "typescript": True, "has_node_modules": True},
                    dead_code_mode=mode,
                )

            arguments = next(
                call.args[3] for call in run.call_args_list if call.args[2] == "dead-code"
            )
            self.assertIn(expected, arguments)
            self.assertNotIn(rejected, arguments)

    def test_type_aware_dead_code_failure_falls_back_and_retains_raw_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            log = root / "invocations.jsonl"
            repo.mkdir()
            binary = root / "fallow"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "from pathlib import Path\n"
                "if '--version' in sys.argv:\n"
                "    print('fallow 3.31.0')\n"
                "    raise SystemExit(0)\n"
                f"with Path({str(log)!r}).open('a') as handle:\n"
                "    handle.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "command = next(arg for arg in sys.argv if arg in "
                "{'config', 'dead-code', 'dupes', 'health', 'flags'})\n"
                "if command == 'dead-code' and '--type-aware' in sys.argv:\n"
                "    print(json.dumps({'error': True, 'message': "
                "'Type-aware analysis failed: sidecar panic\\nstack trace'}))\n"
                "    raise SystemExit(2)\n"
                "if command == 'dead-code':\n"
                "    print(json.dumps({'summary': {'total_issues': 553}, "
                "'total_issues': 553, 'unused_files': []}))\n"
                "    raise SystemExit(1)\n"
                "print(json.dumps({}))\n"
            )
            binary.chmod(0o755)
            with patch.dict("os.environ", {"HANGOVER_FALLOW_BIN": str(binary)}):
                result = run_fallow_scan(
                    repo,
                    run_dir,
                    {"javascript": True, "typescript": True, "has_node_modules": True},
                )

            dead_code = result["commands"]["dead_code"]
            attempts = [
                json.loads(line)
                for line in log.read_text().splitlines()
                if "dead-code" in line
            ]
            type_aware_raw = Path(dead_code["type_aware_attempt"]["raw"])
            type_aware_raw_name = type_aware_raw.name
            type_aware_payload = json.loads(type_aware_raw.read_text())
            type_aware_stderr = Path(dead_code["type_aware_attempt"]["stderr"])
            type_aware_stderr_name = type_aware_stderr.name
            type_aware_stderr_exists = type_aware_stderr.is_file()
            plain_payload = json.loads(
                (run_dir / "fallow" / "dead-code.json").read_text()
            )

        self.assertEqual("completed", result["status"])
        self.assertEqual(1, len(result["warnings"]))
        self.assertIn("type-aware sidecar failed", result["warnings"][0])
        self.assertEqual("completed", dead_code["status"])
        self.assertEqual(553, dead_code["data"]["total_issues"])
        self.assertEqual("type_aware_failed", dead_code["fallback"])
        self.assertEqual(
            "Type-aware analysis failed: sidecar panic", dead_code["fallback_reason"]
        )
        self.assertEqual(2, len(attempts))
        self.assertIn("--type-aware", attempts[0])
        self.assertNotIn("--type-aware", attempts[1])
        self.assertIn("--no-type-aware", attempts[1])
        self.assertEqual("dead-code-type-aware.json", type_aware_raw_name)
        self.assertTrue(type_aware_payload["error"])
        self.assertEqual("dead-code-type-aware.stderr", type_aware_stderr_name)
        self.assertTrue(type_aware_stderr_exists)
        self.assertEqual(553, plain_payload["total_issues"])

    def test_successful_type_aware_dead_code_scan_does_not_fall_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            log = root / "invocations.jsonl"
            repo.mkdir()
            binary = root / "fallow"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "from pathlib import Path\n"
                "if '--version' in sys.argv:\n"
                "    print('fallow 3.31.0')\n"
                "    raise SystemExit(0)\n"
                f"with Path({str(log)!r}).open('a') as handle:\n"
                "    handle.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "command = next(arg for arg in sys.argv if arg in "
                "{'config', 'dead-code', 'dupes', 'health', 'flags'})\n"
                "if command == 'dead-code':\n"
                "    print(json.dumps({'summary': {'total_issues': 7}, "
                "'total_issues': 7, 'unused_files': []}))\n"
                "else:\n"
                "    print(json.dumps({}))\n"
            )
            binary.chmod(0o755)
            with patch.dict("os.environ", {"HANGOVER_FALLOW_BIN": str(binary)}):
                result = run_fallow_scan(
                    repo,
                    run_dir,
                    {"javascript": True, "typescript": True, "has_node_modules": True},
                )

            dead_code = result["commands"]["dead_code"]
            attempts = [
                json.loads(line)
                for line in log.read_text().splitlines()
                if "dead-code" in line
            ]

        self.assertEqual(7, dead_code["data"]["total_issues"])
        self.assertNotIn("fallback", dead_code)
        self.assertEqual(1, len(attempts))
        self.assertIn("--type-aware", attempts[0])

    def test_fallow_error_payload_makes_the_scan_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            repo.mkdir()
            binary = root / "fallow"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "if '--version' in sys.argv:\n"
                "    print('fallow 3.31.0')\n"
                "    raise SystemExit(0)\n"
                "command = next(arg for arg in sys.argv if arg in "
                "{'config', 'dead-code', 'dupes', 'health', 'flags'})\n"
                "if command == 'flags':\n"
                "    print(json.dumps({'error': True, 'message': 'flags crashed'}))\n"
                "    raise SystemExit(1)\n"
                "print(json.dumps({}))\n"
            )
            binary.chmod(0o755)
            with patch.dict("os.environ", {"HANGOVER_FALLOW_BIN": str(binary)}):
                result = run_fallow_scan(
                    repo,
                    run_dir,
                    {"javascript": True, "typescript": False, "has_node_modules": True},
                )

        self.assertEqual("partial", result["status"])
        self.assertEqual("error", result["commands"]["flags"]["status"])
        self.assertEqual("flags crashed", result["commands"]["flags"]["data"]["message"])

    def test_fallow_version_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            run_dir = root / "run"
            repo.mkdir()
            binary = root / "fallow"
            binary.write_text("#!/bin/sh\necho 'fallow 3.13.0'\n")
            binary.chmod(0o755)
            with patch.dict("os.environ", {"HANGOVER_FALLOW_BIN": str(binary)}):
                result = run_fallow_scan(
                    repo,
                    run_dir,
                    {"javascript": True, "typescript": False, "has_node_modules": True},
                )

        self.assertEqual("partial", result["status"])
        self.assertTrue(
            all(
                item["status"] == "version_mismatch"
                for item in result["commands"].values()
            )
        )


class ReviewPacketEvidenceTests(unittest.TestCase):
    def test_packet_carries_fallow_comparison_and_introduced_finding_dispositions(self) -> None:
        from hangover.oracles import prepare_review_packet

        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            run_dir.mkdir()
            snapshot = {
                "id": "verify-2",
                "kind": "verify",
                "inventory": {},
                "fallow": {"status": "completed", "summary": {"dead_code_issues": 27}},
                "fallow_comparison": {"comparable": True, "changes": {}},
                "finding_ids_seen": ["dslp-aaaaaaaaaa"],
            }
            issue = {
                "id": "dslp-issue000001",
                "history": [
                    {
                        "event": "verification_failed",
                        "run": "verify-1",
                        "reasons": [
                            "the fix introduced new deterministic finding(s): "
                            "dslp-aaaaaaaaaa, dslp-bbbbbbbbbb"
                        ],
                    },
                    {"event": "verification_failed", "run": "verify-0", "reasons": ["native check test regressed"]},
                ],
            }
            packet_path = prepare_review_packet(Path(directory), run_dir, "post-fix", snapshot, issue)
            packet = json.loads(packet_path.read_text())

        self.assertEqual({"comparable": True, "changes": {}}, packet["fallow_comparison"])
        self.assertEqual(
            [
                {"id": "dslp-aaaaaaaaaa", "first_reported_in": "verify-1", "present_in_this_scan": True},
                {"id": "dslp-bbbbbbbbbb", "first_reported_in": "verify-1", "present_in_this_scan": False},
            ],
            packet["introduced_findings"],
        )
        self.assertEqual([], packet["implementer_notes"])

    def test_packet_carries_implementer_notes_in_order(self) -> None:
        from hangover.oracles import prepare_review_packet

        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            run_dir.mkdir()
            notes = [
                {"at": "2026-09-07T10:00:00+00:00", "text": "first"},
                {"at": "2026-09-07T11:00:00+00:00", "text": "second"},
            ]
            packet_path = prepare_review_packet(
                Path(directory), run_dir, "post-fix", {"inventory": {}},
                {"id": "dslp-example", "fix_notes": notes},
            )
            packet = json.loads(packet_path.read_text())
        self.assertEqual(notes, packet["implementer_notes"])

    def test_packet_without_issue_has_no_introduced_findings(self) -> None:
        from hangover.oracles import prepare_review_packet

        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            run_dir.mkdir()
            packet_path = prepare_review_packet(
                Path(directory), run_dir, "initial", {"id": "scan-1", "inventory": {}}
            )
            packet = json.loads(packet_path.read_text())

        self.assertEqual([], packet["introduced_findings"])
        self.assertIsNone(packet["fallow_comparison"])


if __name__ == "__main__":
    unittest.main()
