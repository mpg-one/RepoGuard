import sys
from pathlib import Path

import yaml


EXPECTED_INPUTS = {
    "path",
    "fail-on",
    "evidence",
    "baseline",
    "soft-fail",
    "upload-sarif",
    "sarif-file",
}
EXPECTED_OUTPUTS = {"verdict", "risk-level", "exit-code", "sarif-file"}
EXPECTED_DEFAULTS = {
    "path": ".",
    "fail-on": "high",
    "evidence": "none",
    "baseline": "",
    "soft-fail": "false",
    "upload-sarif": "true",
    "sarif-file": "repoguard.sarif",
}
EXPECTED_ACTIONS = {
    "actions/setup-python@v5",
    "github/codeql-action/upload-sarif@v3",
}


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "action.yml")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError("action.yml must contain a mapping")
    if payload.get("runs", {}).get("using") != "composite":
        raise AssertionError("action.yml must declare a composite action")
    if set(payload.get("inputs", {})) != EXPECTED_INPUTS:
        raise AssertionError("action.yml inputs do not match the public contract")
    if set(payload.get("outputs", {})) != EXPECTED_OUTPUTS:
        raise AssertionError("action.yml outputs do not match the public contract")
    defaults = {
        name: metadata.get("default")
        for name, metadata in payload["inputs"].items()
    }
    if defaults != EXPECTED_DEFAULTS:
        raise AssertionError("action.yml input defaults do not match the public contract")
    referenced_actions = {
        step["uses"] for step in payload["runs"].get("steps", []) if "uses" in step
    }
    if referenced_actions != EXPECTED_ACTIONS:
        raise AssertionError("action.yml action references are not pinned as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
