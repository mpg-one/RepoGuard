from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


SEVERITY_POINTS: Dict[str, int] = {
    "info": 1,
    "low": 4,
    "medium": 10,
    "high": 22,
    "critical": 35,
}

RISK_ORDER = {
    "clean": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    path: str
    line: int
    evidence: Optional[str]
    description: str
    recommendation: str

    def to_dict(self) -> Dict[str, object]:
        payload = asdict(self)
        if self.evidence is None:
            payload.pop("evidence")
        return payload


@dataclass(frozen=True)
class ScanStats:
    scanned_files: int = 0
    skipped_files: int = 0
    scanned_bytes: int = 0
    target: str = ""
    source: str = ""


@dataclass
class ScanReport:
    target: str
    source: str
    findings: List[Finding] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0
    scanned_bytes: int = 0
    scan_status: str = "complete"
    truncated: bool = False
    truncation_reason: Optional[str] = None

    @property
    def score(self) -> int:
        raw_score = sum(SEVERITY_POINTS[f.severity] for f in self.findings)
        return min(100, raw_score)

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_POINTS}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def category_scores(self) -> Dict[str, int]:
        scores: Dict[str, int] = {}
        for finding in self.findings:
            scores[finding.category] = scores.get(finding.category, 0) + SEVERITY_POINTS[finding.severity]
        return {category: min(100, score) for category, score in sorted(scores.items())}

    @property
    def risk_level(self) -> str:
        counts = self.severity_counts
        level = "clean"
        if self.score >= 80 or counts["critical"] >= 2:
            level = "critical"
        elif self.score >= 55 or counts["critical"] >= 1 or counts["high"] >= 2:
            level = "high"
        elif self.score >= 25 or counts["high"] >= 1:
            level = "medium"
        elif self.score > 0:
            level = "low"
        if self.truncated and RISK_ORDER[level] < RISK_ORDER["medium"]:
            return "medium"
        return level

    @property
    def verdict(self) -> str:
        if self.truncated:
            return "INCOMPLETE"
        if self.risk_level in {"clean", "low"}:
            return "OK"
        if self.risk_level == "medium":
            return "CAUTION"
        return "DO_NOT_PROCEED"

    @property
    def recommendation(self) -> str:
        if self.truncated:
            return "The scan was incomplete. Do not treat this repository as clean; increase the limit and scan again."
        if self.risk_level == "critical":
            return "Do not load this repository into an AI coding agent without isolation and manual security review."
        if self.risk_level == "high":
            return "Avoid using an AI coding agent here until the highlighted issues are reviewed or sandboxed."
        if self.risk_level == "medium":
            return "Use an AI coding agent only with reduced permissions and review the findings first."
        if self.risk_level == "low":
            return "Low risk signals were found. Review them before giving an agent broad access."
        return "No agent-specific risk signals were found by the current rule set."

    def to_dict(self) -> Dict[str, object]:
        return {
            "tool": "RepoGuard",
            "brand": "RepoGuard by MPG ONE LLC",
            "target": self.target,
            "source": self.source,
            "scan_status": self.scan_status,
            "truncated": self.truncated,
            "truncation_reason": self.truncation_reason,
            "verdict": self.verdict,
            "risk_level": self.risk_level,
            "score": self.score,
            "recommendation": self.recommendation,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "scanned_bytes": self.scanned_bytes,
            "severity_counts": self.severity_counts,
            "category_scores": self.category_scores,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class FileSnapshot:
    root: Path
    path: Path
    relative_path: str
    text: str
