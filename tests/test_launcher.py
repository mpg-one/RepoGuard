import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from repoguard import launcher
from repoguard.scanner import RepoScanner
from tests.fixture_builder import build_suspicious_fixture


ROOT = Path(__file__).resolve().parent.parent
CANARY = "GUARD_OUTSIDE_CANARY_2a71"


def invoke(*arguments: str):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        result = launcher.main(list(arguments))
    return result, stdout.getvalue(), stderr.getvalue()


def write_baseline(path: Path, root: Path) -> None:
    report = RepoScanner().scan(root)
    payload = {
        "baseline_version": 1,
        "tool_version": "0.3.0",
        "generated_at": "2026-01-01T00:00:00Z",
        "fingerprints": {
            finding.fingerprint: {
                "rule_id": finding.rule_id,
                "path": finding.path,
                "first_seen": "2026-01-01T00:00:00Z",
            }
            for finding in report.findings
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


class LauncherDecisionTests(unittest.TestCase):
    def test_clean_workspace_runs_exact_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "safe.txt").write_text("safe content", encoding="utf-8")
            command = ["agent-command", "--flag", "value with spaces"]
            with mock.patch.object(launcher, "exec_command", return_value=7) as execute:
                result, _, stderr = invoke("--path", str(root), "--", *command)

        self.assertEqual(result, 7)
        execute.assert_called_once_with(command)
        self.assertIn("RepoGuard-Guard: PROCEED verdict=OK risk=clean", stderr)

    def test_hostile_workspace_default_deny_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = build_suspicious_fixture(Path(temporary_directory) / "repo")
            with mock.patch.object(launcher, "exec_command", return_value=0) as execute:
                result, _, stderr = invoke("--path", str(root), "--", "agent")

        self.assertEqual(result, launcher.BLOCKED_RISK_EXIT)
        execute.assert_not_called()
        self.assertIn("RepoGuard-Guard: BLOCKED verdict=DO_NOT_PROCEED", stderr)
        self.assertIn("reason=risk_threshold", stderr)

    def test_warn_policy_runs_hostile_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = build_suspicious_fixture(Path(temporary_directory) / "repo")
            with mock.patch.object(launcher, "exec_command", return_value=0) as execute:
                result, _, stderr = invoke(
                    "--path", str(root), "--on-block", "warn", "--", "agent"
                )

        self.assertEqual(result, 0)
        execute.assert_called_once_with(["agent"])
        self.assertIn("RepoGuard-Guard: WARN_PROCEED", stderr)

    def test_prompt_policy_non_tty_denies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = build_suspicious_fixture(Path(temporary_directory) / "repo")
            with mock.patch.object(launcher, "exec_command") as execute:
                result, _, stderr = invoke(
                    "--path", str(root), "--on-block", "prompt", "--", "agent"
                )

        self.assertEqual(result, launcher.BLOCKED_RISK_EXIT)
        execute.assert_not_called()
        self.assertIn("RepoGuard-Guard: BLOCKED", stderr)

    def test_incomplete_blocks_unless_explicitly_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = build_suspicious_fixture(Path(temporary_directory) / "repo")
            with mock.patch.object(launcher, "exec_command", return_value=0) as execute:
                blocked, _, blocked_stderr = invoke(
                    "--path",
                    str(root),
                    "--max-files",
                    "1",
                    "--fail-on",
                    "critical",
                    "--",
                    "agent",
                )
                allowed, _, allowed_stderr = invoke(
                    "--path",
                    str(root),
                    "--max-files",
                    "1",
                    "--fail-on",
                    "critical",
                    "--allow-incomplete",
                    "--",
                    "agent",
                )

        self.assertEqual(blocked, launcher.BLOCKED_INCOMPLETE_EXIT)
        self.assertIn("incomplete=yes reason=max_files", blocked_stderr)
        self.assertEqual(allowed, 0)
        self.assertIn("RepoGuard-Guard: PROCEED verdict=INCOMPLETE", allowed_stderr)
        execute.assert_called_once_with(["agent"])

    def test_force_runs_hostile_workspace_with_audit_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = build_suspicious_fixture(Path(temporary_directory) / "repo")
            with mock.patch.object(launcher, "exec_command", return_value=0) as execute:
                result, _, stderr = invoke("--path", str(root), "--force", "--", "agent")

        self.assertEqual(result, 0)
        execute.assert_called_once_with(["agent"])
        self.assertIn("RepoGuard-Guard: FORCE_PROCEED", stderr)
        self.assertIn("reason=force", stderr)

    def test_repository_policy_files_have_no_implicit_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = build_suspicious_fixture(Path(temporary_directory) / "repo")
            baseline = root / ".repoguard-baseline.json"
            write_baseline(baseline, root)
            (root / ".repoguardignore").write_text("*\n", encoding="utf-8")
            (root / ".env").write_text(
                "REPOGUARD_ON_BLOCK=warn\nREPOGUARD_FAIL_ON=critical\n",
                encoding="utf-8",
            )

            with mock.patch.object(launcher, "exec_command", return_value=0) as execute:
                implicit, _, _ = invoke("--path", str(root), "--", "agent")
                explicit, _, explicit_stderr = invoke(
                    "--path", str(root), "--baseline", str(baseline), "--", "agent"
                )

        self.assertEqual(implicit, launcher.BLOCKED_RISK_EXIT)
        self.assertEqual(explicit, 0)
        execute.assert_called_once_with(["agent"])
        self.assertIn("verdict=OK risk=clean findings=0", explicit_stderr)

    def test_repo_env_is_not_sourced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = build_suspicious_fixture(Path(temporary_directory) / "repo")
            (root / ".env").write_text(
                "REPOGUARD_FORCE=true\nREPOGUARD_ON_BLOCK=warn\n",
                encoding="utf-8",
            )
            with mock.patch.object(launcher, "exec_command") as execute:
                result, _, _ = invoke("--path", str(root), "--", "agent")

        self.assertEqual(result, launcher.BLOCKED_RISK_EXIT)
        execute.assert_not_called()

    def test_missing_separator_or_command_is_operational_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            missing_separator, _, separator_stderr = invoke(
                "--path", str(root), "agent"
            )
            empty_command, _, command_stderr = invoke("--path", str(root), "--")

        self.assertEqual(missing_separator, 1)
        self.assertEqual(empty_command, 1)
        self.assertIn("error=missing_command", separator_stderr)
        self.assertIn("error=missing_command", command_stderr)

    def test_url_path_is_rejected_without_execution(self) -> None:
        with mock.patch.object(launcher, "exec_command") as execute:
            result, _, stderr = invoke(
                "--path", "https://github.com/mpg-one/RepoGuard", "--", "agent"
            )

        self.assertEqual(result, 1)
        execute.assert_not_called()
        self.assertIn("error=scan_failed", stderr)
        self.assertIn("local workspace paths only", stderr)

    def test_symlink_canary_never_appears_in_guard_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "repo"
            root.mkdir()
            outside = base / "outside.txt"
            outside.write_text(CANARY, encoding="utf-8")
            try:
                (root / "linked.txt").symlink_to(outside)
            except (NotImplementedError, OSError) as exc:
                self.skipTest("symlink creation is unavailable: {0}".format(exc))

            with mock.patch.object(launcher, "exec_command", return_value=0):
                result, stdout, stderr = invoke(
                    "--path", str(root), "--print-report", "--", "agent"
                )

        self.assertEqual(result, 0)
        self.assertNotIn(CANARY, stdout)
        self.assertNotIn(CANARY, stderr)


class LauncherIntegrationTests(unittest.TestCase):
    def run_guard(self, root: Path, command):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "repoguard",
                "guard",
                "--path",
                str(root),
                "--on-block",
                "deny",
                "--",
            ]
            + list(command),
            cwd=str(ROOT),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_real_clean_proceed_runs_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "safe.txt").write_text("safe", encoding="utf-8")
            result = self.run_guard(
                root, [sys.executable, "-c", "print('RAN_OK')"]
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "RAN_OK")
        self.assertIn("RepoGuard-Guard: PROCEED", result.stderr)

    def test_nonexistent_command_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            result = self.run_guard(root, ["repoguard-command-that-does-not-exist-91b2"])

        self.assertEqual(result.returncode, 1)
        self.assertIn("RepoGuard-Guard: ERROR error=exec_failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
