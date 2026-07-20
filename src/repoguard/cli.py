import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import BRAND, __version__
from .baseline import Baseline, apply_baseline, load_baseline, write_baseline
from .gitdiff import diff_paths
from .reporters import render_report, risk_meets_threshold
from .scanner import RepoScanner, load_ignore_patterns
from .target import is_git_url, prepare_target


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repoguard",
        description="Static repository risk scanner for AI coding agents. Made by MPG ONE LLC.",
        epilog="Exit codes: 0 complete/below threshold, 1 error, 2 threshold met, 3 incomplete scan.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan",
        help="Scan a local path or public GitHub repository URL.",
        epilog="Exit codes: 0 complete/below threshold, 1 error, 2 threshold met, 3 incomplete scan.",
    )
    scan.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Local path or public https://github.com/ URL to scan. Defaults to the current directory.",
    )
    scan.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Report format. Defaults to text.",
    )
    scan.add_argument("--output", help="Write the report to a file instead of stdout.")
    scan.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Print a one-line text verdict. Ignored for JSON and SARIF.",
    )
    scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help="Exit with status 2 if the final risk level is at or above this threshold.",
    )
    scan.add_argument(
        "--max-file-bytes",
        type=non_negative_int,
        default=1_000_000,
        help="Skip files larger than this size. Defaults to 1000000.",
    )
    scan.add_argument(
        "--max-files",
        type=non_negative_int,
        default=10_000,
        help="Stop after this many eligible files. Defaults to 10000.",
    )
    scan.add_argument(
        "--max-total-bytes",
        type=non_negative_int,
        default=200_000_000,
        help="Stop before scanned bytes exceed this total. Defaults to 200000000.",
    )
    scan.add_argument(
        "--max-seconds",
        type=non_negative_float,
        default=120,
        help="Stop when this wall-clock duration is reached. Defaults to 120.",
    )
    scan.add_argument(
        "--evidence",
        choices=["safe", "none", "snippet"],
        default="safe",
        help="Evidence policy. Defaults to safe synthetic labels; use none for CI uploads.",
    )
    scan.add_argument(
        "--ignore-file",
        help="Optional ignore file with gitignore-style patterns. Not loaded automatically for safety.",
    )
    scan.add_argument(
        "--baseline",
        help="Explicit baseline JSON file. Baselines are never loaded automatically.",
    )
    scan.add_argument(
        "--show-baselined",
        action="store_true",
        help="Include suppressed findings in text output marked as baselined.",
    )
    scan.add_argument(
        "--update-baseline",
        action="store_true",
        help="Rewrite the explicit baseline from the complete current scan.",
    )
    scan.add_argument(
        "--diff",
        metavar="REF",
        help="Scan changed and untracked files relative to a local Git ref.",
    )
    return parser


def normalize_argv(argv: Optional[List[str]]) -> List[str]:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return ["scan"]
    if args and args[0] not in {"scan", "--help", "-h", "--version"}:
        return ["scan"] + args
    return args


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(normalize_argv(argv))
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "scan":
        return run_scan(args)
    parser.error(f"Unknown command: {args.command}")
    return 1


def run_scan(args: argparse.Namespace) -> int:
    prepared = None
    try:
        if args.update_baseline and not args.baseline:
            raise ValueError("--update-baseline requires --baseline <path>.")
        if args.diff and is_git_url(args.target):
            raise ValueError("--diff supports local Git targets only; URL targets are not supported.")

        baseline_path = Path(args.baseline).expanduser() if args.baseline else None
        baseline = Baseline(fingerprints={})
        if baseline_path is not None and (not args.update_baseline or baseline_path.exists()):
            baseline = load_baseline(baseline_path)

        prepared = prepare_target(args.target)
        ignore_patterns = load_ignore_patterns(Path(args.ignore_file)) if args.ignore_file else []
        selected_paths = diff_paths(prepared.path, args.diff) if args.diff else None
        scanner = RepoScanner(
            max_file_bytes=args.max_file_bytes,
            max_files=args.max_files,
            max_total_bytes=args.max_total_bytes,
            max_duration_seconds=args.max_seconds,
            ignore_patterns=ignore_patterns,
            evidence_mode=args.evidence,
        )
        report = scanner.scan(
            prepared.path,
            target=prepared.original,
            source=prepared.source,
            selected_paths=selected_paths,
            scan_mode="diff" if args.diff else "full",
            diff_base=args.diff,
        )
        if baseline_path is not None:
            apply_baseline(report, baseline)

        if args.update_baseline and report.truncated:
            rendered = render_report(
                report,
                args.format,
                show_baselined=args.show_baselined,
                quiet=args.quiet and args.format == "text",
            )
            _write_output(rendered, args.output)
            print(
                "{0}: error: refusing to update a baseline from an incomplete scan".format(BRAND),
                file=sys.stderr,
            )
            return 3
        if args.update_baseline and baseline_path is not None:
            write_baseline(baseline_path, report, baseline)

        rendered = render_report(
            report,
            args.format,
            show_baselined=args.show_baselined,
            quiet=args.quiet and args.format == "text",
        )
        _write_output(rendered, args.output)
        if report.truncated:
            return 3
        if args.fail_on and risk_meets_threshold(report.risk_level, args.fail_on):
            return 2
        return 0
    except Exception as exc:
        print(f"{BRAND}: error: {exc}", file=sys.stderr)
        return 1
    finally:
        if prepared is not None:
            prepared.cleanup()


def _write_output(rendered: str, output_path: Optional[str]) -> None:
    if output_path:
        Path(output_path).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    raise SystemExit(main())
