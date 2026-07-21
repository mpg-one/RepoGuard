import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .baseline import Baseline, apply_baseline, load_baseline
from .models import ScanReport
from .reporters import render_report, risk_meets_threshold
from .scanner import RepoScanner
from .target import is_git_url


BLOCKED_RISK_EXIT = 20
BLOCKED_INCOMPLETE_EXIT = 21


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def non_negative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def add_guard_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--path",
        default=".",
        help="Local workspace to scan before execution. Defaults to the current directory.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Block when risk reaches this threshold. Defaults to high.",
    )
    parser.add_argument(
        "--evidence",
        choices=["safe", "none", "snippet"],
        default="safe",
        help="Evidence policy for the optional full report. Defaults to safe.",
    )
    parser.add_argument(
        "--baseline",
        help="Explicit baseline JSON file. Baselines are never loaded automatically.",
    )
    parser.add_argument(
        "--on-block",
        choices=["deny", "prompt", "warn"],
        default="deny",
        help="Risk-threshold policy. Defaults to deny.",
    )
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Proceed after an incomplete scan and emit an explicit audit record.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Run the command despite a risk or incomplete-scan block.",
    )
    parser.add_argument(
        "--print-report",
        action="store_true",
        help="Print the full text report to stderr before the decision record.",
    )
    parser.add_argument("--max-file-bytes", type=non_negative_int, default=1_000_000)
    parser.add_argument("--max-files", type=non_negative_int, default=10_000)
    parser.add_argument("--max-total-bytes", type=non_negative_int, default=200_000_000)
    parser.add_argument("--max-seconds", type=non_negative_float, default=120)
    parser.add_argument(
        "agent_command",
        nargs=argparse.REMAINDER,
        help="Command and arguments to run after the required -- separator.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repoguard-exec",
        description="Scan a local workspace before starting an AI coding agent.",
        epilog=(
            "Exit codes: child code on proceed, 1 operational error, "
            "20 risk block, 21 incomplete-scan block."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    add_guard_arguments(parser)
    return parser


def exec_command(command: Sequence[str]) -> int:
    if os.name == "nt":
        # Windows has no exec-style process replacement; RepoGuard remains the
        # parent wrapper and passes the child's return code through unchanged.
        return subprocess.run(list(command), check=False).returncode
    os.execvp(command[0], list(command))
    return 1


def run_guard(args: argparse.Namespace, separator_present: bool = True) -> int:
    command = list(args.agent_command)
    if command and command[0] == "--":
        command = command[1:]
    if not separator_present or not command:
        return _operational_error("missing_command", "a command is required after --")

    try:
        if is_git_url(args.path):
            raise ValueError("guard accepts local workspace paths only; use scan for URLs")
        workspace = Path(args.path).expanduser()
        if not workspace.exists():
            raise FileNotFoundError("workspace does not exist: {0}".format(workspace))
        if not workspace.is_dir():
            raise ValueError("workspace must be a directory: {0}".format(workspace))
        workspace = workspace.resolve()

        baseline = Baseline(fingerprints={})
        if args.baseline:
            baseline = load_baseline(Path(args.baseline).expanduser())

        scanner = RepoScanner(
            max_file_bytes=args.max_file_bytes,
            max_files=args.max_files,
            max_total_bytes=args.max_total_bytes,
            max_duration_seconds=args.max_seconds,
            evidence_mode=args.evidence,
        )
        report = scanner.scan(
            workspace,
            target=args.path,
            source="local",
            scan_mode="full",
        )
        if args.baseline:
            apply_baseline(report, baseline)
    except Exception as exc:
        return _operational_error("scan_failed", str(exc))

    if args.print_report:
        print(render_report(report, "text"), file=sys.stderr)

    if report.truncated:
        if args.force:
            _print_record("FORCE_PROCEED", report, "force")
            return _execute(command)
        if not args.allow_incomplete:
            _print_record("BLOCKED", report, report.truncation_reason or "incomplete")
            return BLOCKED_INCOMPLETE_EXIT
        _print_record("PROCEED", report, "incomplete_allowed")
        return _execute(command)

    risk_block = risk_meets_threshold(report.risk_level, args.fail_on)
    if risk_block:
        if args.force:
            _print_record("FORCE_PROCEED", report, "force")
            return _execute(command)
        if args.on_block == "warn":
            _print_record("WARN_PROCEED", report, "risk_threshold")
            return _execute(command)
        if args.on_block == "prompt" and sys.stdin.isatty() and sys.stdout.isatty():
            print("Proceed anyway? [y/N] ", end="", flush=True)
            answer = sys.stdin.readline().strip().lower()
            if answer in {"y", "yes"}:
                _print_record("PROCEED", report, "prompt_accepted")
                return _execute(command)
        _print_record("BLOCKED", report, "risk_threshold")
        return BLOCKED_RISK_EXIT

    _print_record("PROCEED", report, "policy_passed")
    return _execute(command)


def _execute(command: Sequence[str]) -> int:
    try:
        return exec_command(command)
    except Exception as exc:
        return _operational_error("exec_failed", str(exc))


def _print_record(action: str, report: ScanReport, reason: str) -> None:
    print(
        "RepoGuard-Guard: {0} verdict={1} risk={2} findings={3} "
        "incomplete={4} reason={5}".format(
            action,
            report.verdict,
            report.risk_level,
            report.new_findings,
            "yes" if report.truncated else "no",
            reason,
        ),
        file=sys.stderr,
        flush=True,
    )


def _operational_error(error: str, detail: str) -> int:
    sanitized = " ".join(detail.split())
    print(
        "RepoGuard-Guard: ERROR error={0} detail={1}".format(
            error, json.dumps(sanitized)
        ),
        file=sys.stderr,
        flush=True,
    )
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    try:
        args = parser.parse_args(raw_args)
    except SystemExit as exc:
        if exc.code == 0:
            return 0
        return _operational_error("bad_arguments", "argument parsing failed")
    return run_guard(args, separator_present="--" in raw_args)


if __name__ == "__main__":
    raise SystemExit(main())
