import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from . import __version__
from .models import ScanReport


BASELINE_VERSION = 1


@dataclass(frozen=True)
class Baseline:
    fingerprints: Dict[str, Dict[str, str]]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_baseline(path: Path) -> Baseline:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("Malformed baseline JSON in {0}: {1}".format(path, exc)) from exc
    except OSError as exc:
        raise FileNotFoundError("Could not read baseline file: {0}".format(path)) from exc

    if not isinstance(payload, dict):
        raise ValueError("Malformed baseline JSON in {0}: expected an object".format(path))
    version = payload.get("baseline_version")
    if not isinstance(version, int) or isinstance(version, bool) or version != BASELINE_VERSION:
        raise ValueError(
            "Unsupported baseline_version {0!r}; expected {1}.".format(version, BASELINE_VERSION)
        )
    if not isinstance(payload.get("tool_version"), str) or not isinstance(
        payload.get("generated_at"), str
    ):
        raise ValueError(
            "Malformed baseline JSON in {0}: tool_version and generated_at are required".format(path)
        )
    fingerprints = payload.get("fingerprints")
    if not isinstance(fingerprints, dict):
        raise ValueError("Malformed baseline JSON in {0}: fingerprints must be an object".format(path))

    validated: Dict[str, Dict[str, str]] = {}
    for fingerprint, metadata in fingerprints.items():
        if not isinstance(fingerprint, str) or not isinstance(metadata, dict):
            raise ValueError("Malformed baseline JSON in {0}: invalid fingerprint entry".format(path))
        if len(fingerprint) != 64 or any(character not in "0123456789abcdef" for character in fingerprint):
            raise ValueError("Malformed baseline JSON in {0}: invalid SHA-256 fingerprint".format(path))
        rule_id = metadata.get("rule_id")
        finding_path = metadata.get("path")
        first_seen = metadata.get("first_seen")
        if not all(isinstance(value, str) for value in (rule_id, finding_path, first_seen)):
            raise ValueError("Malformed baseline JSON in {0}: invalid fingerprint metadata".format(path))
        validated[fingerprint] = {
            "rule_id": rule_id,
            "path": finding_path,
            "first_seen": first_seen,
        }
    return Baseline(fingerprints=validated)


def apply_baseline(report: ScanReport, baseline: Baseline) -> None:
    new_findings = []
    baselined_findings = []
    for finding in report.findings:
        if finding.fingerprint in baseline.fingerprints:
            baselined_findings.append(finding)
        else:
            new_findings.append(finding)
    report.findings = new_findings
    report.baselined = baselined_findings


def write_baseline(path: Path, report: ScanReport, previous: Baseline) -> None:
    now = utc_now()
    fingerprints: Dict[str, Dict[str, str]] = {}
    for finding in report.all_findings:
        old_metadata = previous.fingerprints.get(finding.fingerprint, {})
        fingerprints[finding.fingerprint] = {
            "rule_id": finding.rule_id,
            "path": finding.path,
            "first_seen": old_metadata.get("first_seen", now),
        }
    payload = {
        "baseline_version": BASELINE_VERSION,
        "tool_version": __version__,
        "generated_at": now,
        "fingerprints": fingerprints,
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(path.parent), prefix=".repoguard-baseline-", delete=False
        ) as handle:
            handle.write(rendered)
            temporary_path = Path(handle.name)
        os.replace(str(temporary_path), str(path))
    except OSError as exc:
        raise OSError("Could not write baseline file: {0}".format(path)) from exc
    finally:
        if temporary_path is not None and temporary_path.exists():
            try:
                temporary_path.unlink()
            except OSError:
                pass
