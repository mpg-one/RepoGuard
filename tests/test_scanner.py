import json
import subprocess
import sys
import unittest
from pathlib import Path

from repoguard.scanner import RepoScanner
from tests.fixture_builder import suspicious_fixture


ROOT = Path(__file__).resolve().parent.parent


class ScannerTests(unittest.TestCase):
    def test_suspicious_fixture_is_high_or_critical_risk(self) -> None:
        with suspicious_fixture() as fixture:
            report = RepoScanner().scan(fixture)
            rule_ids = {finding.rule_id for finding in report.findings}

        self.assertIn(report.risk_level, {"high", "critical"})
        self.assertGreaterEqual(report.score, 80)
        self.assertIn("agent-prompt-injection", rule_ids)
        self.assertIn("exfil-sensitive-network", rule_ids)
        self.assertIn("package-lifecycle-script", rule_ids)
        self.assertIn("github-actions-pull-request-target", rule_ids)

    def test_clean_fixture_has_no_findings(self) -> None:
        report = RepoScanner().scan(ROOT / "tests" / "fixtures" / "clean-repo")

        self.assertEqual(report.risk_level, "clean")
        self.assertEqual(report.score, 0)
        self.assertEqual(report.findings, [])

    def test_cli_json_output(self) -> None:
        with suspicious_fixture() as fixture:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repoguard",
                    "scan",
                    str(fixture),
                    "--format",
                    "json",
                ],
                cwd=str(ROOT),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        payload = json.loads(result.stdout)

        self.assertEqual(payload["tool"], "RepoGuard")
        self.assertEqual(payload["brand"], "RepoGuard by MPG ONE LLC")
        self.assertEqual(payload["scan_status"], "complete")
        self.assertEqual(payload["verdict"], "DO_NOT_PROCEED")
        self.assertIn(payload["risk_level"], {"high", "critical"})
        self.assertGreater(payload["findings"], [])
        self.assertTrue(all(finding.get("evidence") for finding in payload["findings"]))

    def test_cli_fail_on_threshold(self) -> None:
        with suspicious_fixture() as fixture:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repoguard",
                    "scan",
                    str(fixture),
                    "--format",
                    "json",
                    "--fail-on",
                    "high",
                ],
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        self.assertEqual(result.returncode, 2)

    def test_cli_help_uses_company_branding(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "repoguard", "--help"],
            cwd=str(ROOT),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertIn("MPG ONE LLC", result.stdout)


if __name__ == "__main__":
    unittest.main()
