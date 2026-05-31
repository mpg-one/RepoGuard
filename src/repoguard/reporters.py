import json
from typing import Dict, Iterable, List

from . import BRAND, __version__
from .models import Finding, ScanReport, SEVERITY_POINTS


def render_text(report: ScanReport) -> str:
    lines: List[str] = [
        BRAND,
        "=" * len(BRAND),
        f"Version: {__version__}",
        f"Target: {report.target}",
        f"Source: {report.source}",
        f"Risk: {report.risk_level.title()}",
        f"Score: {report.score}/100",
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

    lines.extend(["", "Recommendation:", f"  {report.recommendation}"])
    return "\n".join(lines)


def render_text_finding(finding: Finding) -> List[str]:
    location = finding.path
    if finding.line:
        location = f"{location}:{finding.line}"
    return [
        f"  - {finding.severity.upper()} {finding.rule_id} {location}",
        f"    {finding.title}",
        f"    Evidence: {finding.evidence or 'n/a'}",
        f"    Fix: {finding.recommendation}",
    ]


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
                "properties": {
                    "brand": BRAND,
                    "risk_level": report.risk_level,
                    "score": report.score,
                    "recommendation": report.recommendation,
                    "scanned_files": report.scanned_files,
                    "skipped_files": report.skipped_files,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def sarif_result(finding: Finding) -> Dict[str, object]:
    return {
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": {"text": f"{finding.title} Evidence: {finding.evidence}"},
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


def render_report(report: ScanReport, output_format: str) -> str:
    if output_format == "text":
        return render_text(report)
    if output_format == "json":
        return render_json(report)
    if output_format == "sarif":
        return render_sarif(report)
    raise ValueError(f"Unsupported output format: {output_format}")


def risk_meets_threshold(risk_level: str, threshold: str) -> bool:
    order = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order[risk_level] >= order[threshold]

