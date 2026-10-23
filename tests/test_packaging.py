"""`npm install -g` is hangover's install route: the package names a `hangover` bin, carries the runtime
(Python source, schemas, prompts, skill) but no development material, depends on the pinned analyzers
at run time, and its launcher finds the package through the symlink npm puts on PATH."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANALYZERS = {"@ast-grep/cli", "fallow", "jscpd"}


class PackageManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.package = json.loads((ROOT / "package.json").read_text())

    def test_the_package_installs_both_command_names(self) -> None:
        self.assertEqual("agent-hangover", self.package["name"])
        self.assertEqual({"hangover": "bin/hangover", "agent-hangover": "bin/hangover"},
                         self.package.get("bin"))
        self.assertTrue(os.access(ROOT / "bin" / "hangover", os.X_OK))

    def test_the_analyzers_are_runtime_dependencies_with_exact_pins(self) -> None:
        dependencies = self.package.get("dependencies") or {}
        self.assertEqual(ANALYZERS, set(dependencies))
        self.assertFalse(ANALYZERS & set(self.package.get("devDependencies") or {}))
        for name, version in dependencies.items():
            self.assertRegex(version, r"^\d+\.\d+\.\d+$", f"{name} is not pinned exactly")
        lock = json.loads((ROOT / "package-lock.json").read_text())["packages"][""]
        self.assertEqual(dependencies, lock.get("dependencies"), "package-lock.json is out of date")

    @unittest.skipUnless(shutil.which("npm"), "npm is needed to list the package's files")
    def test_the_tarball_ships_the_runtime_and_no_development_material(self) -> None:
        listed = subprocess.run(["npm", "pack", "--dry-run", "--json", "--ignore-scripts"], cwd=ROOT,
                                capture_output=True, text=True, check=True)
        files = {entry["path"] for entry in json.loads(listed.stdout)[0]["files"]}
        source = {f"src/hangover/{path.name}" for path in (ROOT / "src" / "hangover").glob("*.py")}
        required = {"bin/hangover", "package.json", "README.md", "CHANGELOG.md", "LICENSE", "schemas/review.schema.json",
                    "skills/hangover/SKILL.md", *source,
                    *(f"prompts/{path.name}" for path in (ROOT / "prompts").glob("*.md"))}
        self.assertEqual(set(), required - files, "missing from the tarball")
        private = sorted(path for path in files
                         if path.startswith(("tests/", "docs/research/", "docs/reviews/", ".beads/", ".codex/",
                                             ".claude/", ".agents/", "node_modules/"))
                         or path in {"STATE.md", "AGENTS.md", "CLAUDE.md", ".fallowrc.json"}
                         or path.endswith(".pyc"))
        self.assertEqual([], private, "development material in the tarball")


class LauncherTests(unittest.TestCase):
    def test_python_module_execution_uses_the_public_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "-m", "hangover", "--version"], cwd=directory,
                                    capture_output=True, text=True,
                                    env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertRegex(result.stdout, r"^hangover \d+\.\d+\.\d+")

    def test_the_launcher_resolves_the_package_through_a_symlink_from_any_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory) / "bin"
            bin_dir.mkdir()
            (bin_dir / "hangover").symlink_to(ROOT / "bin" / "hangover")
            elsewhere = Path(directory) / "elsewhere"
            elsewhere.mkdir()
            environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
            result = subprocess.run([sys.executable, str(bin_dir / "hangover"), "--version"], cwd=elsewhere,
                                    capture_output=True, text=True, env=environment)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertRegex(result.stdout, r"^hangover \d+\.\d+\.\d+")

    def test_the_launcher_imports_nothing_from_pythonpath_or_the_current_directory(self) -> None:
        # Python runs isolated (-I): a module planted on PYTHONPATH or in the working directory never
        # shadows the standard library or hangover itself.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = root / "planted-module-ran"
            planted = root / "planted"
            (planted / "hangover").mkdir(parents=True)
            for name in ("pathlib.py", "argparse.py", "json.py", "hangover/__init__.py", "hangover/cli.py"):
                (planted / name).write_text(f"open({str(canary)!r}, 'a').write({name!r})\n")
            environment = {**{key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
                           "PYTHONPATH": str(planted)}
            result = subprocess.run([sys.executable, str(ROOT / "bin" / "hangover"), "--version"], cwd=planted,
                                    capture_output=True, text=True, env=environment)
            self.assertTrue(planted.is_dir(), "precondition: the planted modules exist")
            self.assertFalse(canary.exists(), f"a planted module ran: {canary.read_text() if canary.exists() else ''}")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertRegex(result.stdout, r"^hangover \d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
