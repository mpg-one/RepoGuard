import json
from typing import Dict, Iterable, List

from . import BRAND, __version__
from .models import Finding, ScanReport, SEVERITY_POINTS


def render_text(report: ScanReport, show_baselined: bool = False) -> str:
    if report.truncated:
        status = "INCOMPLETE ({0} limit reached)".format(report.truncation_reason)
    else:
        status = "COMPLETE"
    lines: List[str] = [
        BRAND,
        "=" * len(BRAND),
        f"Version: {__version__}",
        f"Target: {report.target}",
        f"Source: {report.source}",
        "Mode: {0}".format(
            "diff vs {0}".format(report.diff_base) if report.scan_mode == "diff" else "full"
        ),
        f"Status: {status}",
        f"Verdict: {report.verdict}",
        f"Risk: {report.risk_level.title()}",
        f"Score: {report.score}/100",
        f"New findings: {report.new_findings}",
        f"Baselined findings: {report.baselined_findings}",
        f"Scanned files: {report.scanned_files}",
        f"Skipped files: {report.skipped_files}",
        "",
        "Category scores:",
    ]
    if report.category_scores:
        for category, score in report.category_scores.items():
            lines.append(f"  - {category}: {score}/100")
    else:
        lines.append("  - none")

    lines.extend(["", "Findings:"])
    if not report.findings:
        lines.append("  No findings.")
    else:
        for finding in report.findings:
            lines.extend(render_text_finding(finding))

    if show_baselined and report.baselined:
        lines.extend(["", "Baselined findings:"])
        for finding in report.baselined:
            lines.extend(render_text_finding(finding, baselined=True))

    lines.extend(["", "Recommendation:", f"  {report.recommendation}"])
    return "\n".join(lines)


def render_text_finding(finding: Finding, baselined: bool = False) -> List[str]:
    location = finding.path
    if finding.line:
        location = f"{location}:{finding.line}"
    lines = [
        "  - {0}{1} {2} {3}".format(
            "[baselined] " if baselined else "",
            finding.severity.upper(),
            finding.rule_id,
            location,
        ),
        f"    {finding.title}",
    ]
    if finding.evidence is not None:
        lines.append(f"    Evidence: {finding.evidence}")
    lines.append(f"    Fix: {finding.recommendation}")
    return lines


def render_quiet(report: ScanReport) -> str:
    if report.truncated:
        return "RepoGuard: INCOMPLETE ({0} limit) — scan truncated, results unreliable.".format(
            report.truncation_reason
        )
    total_findings = report.new_findings + report.baselined_findings
    return (
        "RepoGuard: {0} — {1} risk, {2} findings ({3} new, {4} baselined) "
        "in {5} files. Run without --quiet for details."
    ).format(
        report.verdict,
        report.risk_level,
        total_findings,
        report.new_findings,
        report.baselined_findings,
        report.scanned_files,
    )


def render_json(report: ScanReport) -> str:
    payload = report.to_dict()
    payload["version"] = __version__
    return json.dumps(payload, indent=2, sort_keys=True)


def render_sarif(report: ScanReport) -> str:
    rules = {}
    for finding in report.findings:
        if finding.rule_id in rules:
            continue
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": finding.recommendation},
            "properties": {
                "category": finding.category,
                "severity": finding.severity,
                "precision": "medium",
            },
        }

    invocation: Dict[str, object] = {"executionSuccessful": not report.truncated}
    if report.truncated:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "error",
                "message": {
                    "text": "RepoGuard scan incomplete: {0} limit reached.".format(report.truncation_reason)
                },
            }
        ]

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RepoGuard",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/mpg-one/repoguard",
                        "rules": list(rules.values()),
                    }
                },
                "results": [sarif_result(finding) for finding in report.findings],
                "invocations": [invocation],
                "properties": {
                    "brand": BRAND,
                    "scan_status": report.scan_status,
                    "truncated": report.truncated,
                    "truncation_reason": report.truncation_reason,
                    "verdict": report.verdict,
                    "scan_mode": report.scan_mode,
                    "diff_base": report.diff_base,
                    "risk_level": report.risk_level,
                    "score": report.score,
                    "recommendation": report.recommendation,
                    "new_findings": report.new_findings,
                    "baselined_findings": report.baselined_findings,
                    "scanned_files": report.scanned_files,
                    "skipped_files": report.skipped_files,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def sarif_result(finding: Finding) -> Dict[str, object]:
    message = finding.title
    if finding.evidence is not None:
        message = f"{message} Evidence: {finding.evidence}"
    return {
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {"startLine": max(finding.line, 1)},
                }
            }
        ],
        "properties": {
            "category": finding.category,
            "severity": finding.severity,
        },
    }


def sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def render_report(
    report: ScanReport,
    output_format: str,
    show_baselined: bool = False,
    quiet: bool = False,
) -> str:
    if output_format == "text":
        if quiet:
            return render_quiet(report)
        return render_text(report, show_baselined=show_baselined)
    if output_format == "json":
        return render_json(report)
    if output_format == "sarif":
        return render_sarif(report)
    raise ValueError(f"Unsupported output format: {output_format}")


def risk_meets_threshold(risk_level: str, threshold: str) -> bool:
    order = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order[risk_level] >= order[threshold]
