from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

from .models import FileSnapshot, Finding, ScanReport
from .rules import CUSTOM_RULES, REGEX_RULES


EXCLUDED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
}

TEXT_EXTENSIONS = {
    "",
    ".bash",
    ".c",
    ".cfg",
    ".cmd",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".dockerfile",
    ".env",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".lock",
    ".lua",
    ".mjs",
    ".md",
    ".mdx",
    ".php",
    ".pl",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

TEXT_FILE_NAMES = {
    "Dockerfile",
    "Makefile",
    "Rakefile",
    "Gemfile",
    "Pipfile",
    "requirements.txt",
    "package.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Cargo.toml",
    "go.mod",
    "go.sum",
}


class RepoScanner:
    def __init__(self, max_file_bytes: int = 1_000_000, ignore_patterns: Optional[Iterable[str]] = None) -> None:
        self.max_file_bytes = max_file_bytes
        self.ignore_patterns = [pattern.strip() for pattern in ignore_patterns or [] if pattern.strip()]

    def scan(self, root: Path, target: Optional[str] = None, source: Optional[str] = None) -> ScanReport:
        root = root.resolve()
        findings: List[Finding] = []
        scanned_files = 0
        skipped_files = 0
        scanned_bytes = 0

        for path in self.iter_files(root):
            try:
                size = path.stat().st_size
            except OSError:
                skipped_files += 1
                continue
            if size > self.max_file_bytes:
                skipped_files += 1
                continue
            snapshot = self.read_snapshot(root, path)
            if snapshot is None:
                skipped_files += 1
                continue

            scanned_files += 1
            scanned_bytes += size
            findings.extend(self.scan_snapshot(snapshot))

        findings.sort(key=lambda item: (-self._severity_rank(item.severity), item.path, item.line, item.rule_id))
        return ScanReport(
            target=target or str(root),
            source=source or str(root),
            findings=findings,
            scanned_files=scanned_files,
            skipped_files=skipped_files,
            scanned_bytes=scanned_bytes,
        )

    def iter_files(self, root: Path) -> Iterator[Path]:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in EXCLUDED_DIR_NAMES for part in path.relative_to(root).parts[:-1]):
                continue
            relative_path = path.relative_to(root).as_posix()
            if self.is_ignored(relative_path):
                continue
            if not self.is_probably_text(path):
                continue
            yield path

    def read_snapshot(self, root: Path, path: Path) -> Optional[FileSnapshot]:
        try:
            data = path.read_bytes()
        except OSError:
            return None
        if b"\x00" in data:
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace")
        relative_path = path.relative_to(root).as_posix()
        return FileSnapshot(root=root, path=path, relative_path=relative_path, text=text)

    def scan_snapshot(self, snapshot: FileSnapshot) -> Iterable[Finding]:
        findings: List[Finding] = []
        for rule in REGEX_RULES:
            findings.extend(rule.scan(snapshot))
        for rule in CUSTOM_RULES:
            findings.extend(rule(snapshot))
        return self.dedupe(findings)

    @staticmethod
    def is_probably_text(path: Path) -> bool:
        return path.name in TEXT_FILE_NAMES or path.suffix.lower() in TEXT_EXTENSIONS

    def is_ignored(self, relative_path: str) -> bool:
        for pattern in self.ignore_patterns:
            if ignore_match(relative_path, pattern):
                return True
        return False

    @staticmethod
    def dedupe(findings: Iterable[Finding]) -> List[Finding]:
        seen = set()
        unique: List[Finding] = []
        for item in findings:
            key = (item.rule_id, item.path, item.line, item.evidence)
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)


def load_ignore_patterns(path: Optional[Path]) -> List[str]:
    if path is None:
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise FileNotFoundError(f"Could not read ignore file: {path}") from exc
    patterns = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        patterns.append(stripped)
    return patterns


def ignore_match(relative_path: str, pattern: str) -> bool:
    pattern = pattern.strip()
    if not pattern or pattern.startswith("#"):
        return False
    if pattern.startswith("!"):
        return False

    relative_path = relative_path.strip("/")
    pattern = pattern.lstrip("/")

    if pattern.endswith("/"):
        prefix = pattern.rstrip("/")
        return relative_path == prefix or relative_path.startswith(prefix + "/")

    if "/" not in pattern:
        return fnmatch(Path(relative_path).name, pattern) or any(
            fnmatch(part, pattern) for part in Path(relative_path).parts
        )

    return fnmatch(relative_path, pattern) or relative_path.startswith(pattern.rstrip("*").rstrip("/"))
