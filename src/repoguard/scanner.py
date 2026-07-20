import os
import stat
import time
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
    def __init__(
        self,
        max_file_bytes: int = 1_000_000,
        max_files: int = 10_000,
        max_total_bytes: int = 200_000_000,
        max_duration_seconds: float = 120,
        ignore_patterns: Optional[Iterable[str]] = None,
        evidence_mode: str = "safe",
    ) -> None:
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_duration_seconds = max_duration_seconds
        self.ignore_patterns = [pattern.strip() for pattern in ignore_patterns or [] if pattern.strip()]
        self.evidence_mode = evidence_mode
        self._deadline = float("inf")
        self._traversal_skipped = 0
        self._encountered_files = 0
        self._truncation_reason: Optional[str] = None

    def scan(
        self,
        root: Path,
        target: Optional[str] = None,
        source: Optional[str] = None,
        selected_paths: Optional[Iterable[str]] = None,
        scan_mode: str = "full",
        diff_base: Optional[str] = None,
    ) -> ScanReport:
        root = root.resolve()
        self._deadline = time.monotonic() + self.max_duration_seconds
        self._traversal_skipped = 0
        self._encountered_files = 0
        self._truncation_reason = None
        findings: List[Finding] = []
        scanned_files = 0
        skipped_files = 0
        scanned_bytes = 0

        for path in self.iter_files(root, selected_paths):
            if self._limit_reached("max_duration", time.monotonic() >= self._deadline):
                break
            try:
                path_stat = os.lstat(str(path))
            except OSError:
                skipped_files += 1
                continue
            if not stat.S_ISREG(path_stat.st_mode):
                skipped_files += 1
                continue
            size = path_stat.st_size
            if size > self.max_file_bytes:
                skipped_files += 1
                continue
            if self._limit_reached("max_total_bytes", scanned_bytes + size > self.max_total_bytes):
                break
            snapshot = self.read_snapshot(root, path)
            if snapshot is None:
                skipped_files += 1
                continue

            scanned_files += 1
            scanned_bytes += size
            findings.extend(self.scan_snapshot(snapshot))
            if self._limit_reached("max_duration", time.monotonic() >= self._deadline):
                break

        findings.sort(key=lambda item: (-self._severity_rank(item.severity), item.path, item.line, item.rule_id))
        truncated = self._truncation_reason is not None
        return ScanReport(
            target=target or str(root),
            source=source or str(root),
            findings=findings,
            scanned_files=scanned_files,
            skipped_files=skipped_files + self._traversal_skipped,
            scanned_bytes=scanned_bytes,
            scan_status="incomplete" if truncated else "complete",
            truncated=truncated,
            truncation_reason=self._truncation_reason,
            scan_mode=scan_mode,
            diff_base=diff_base,
        )

    def iter_files(self, root: Path, selected_paths: Optional[Iterable[str]] = None) -> Iterator[Path]:
        if selected_paths is not None:
            yield from self._iter_selected_files(root, selected_paths)
            return

        root_real = os.path.realpath(str(root))
        directories = [root]
        while directories:
            if time.monotonic() >= self._deadline:
                self._mark_truncated("max_duration")
                return
            directory = directories.pop()
            try:
                directory_stat = os.lstat(str(directory))
            except OSError:
                self._traversal_skipped += 1
                continue
            if not stat.S_ISDIR(directory_stat.st_mode) or not self._is_contained(root_real, str(directory)):
                self._traversal_skipped += 1
                continue
            try:
                with os.scandir(str(directory)) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name)
            except OSError:
                self._traversal_skipped += 1
                continue

            child_directories: List[Path] = []
            for entry in entries:
                if time.monotonic() >= self._deadline:
                    self._mark_truncated("max_duration")
                    return
                path = Path(entry.path)
                try:
                    entry_stat = os.lstat(entry.path)
                except OSError:
                    self._traversal_skipped += 1
                    continue

                if stat.S_ISLNK(entry_stat.st_mode):
                    self._traversal_skipped += 1
                    continue
                if entry.is_dir(follow_symlinks=False) and stat.S_ISDIR(entry_stat.st_mode):
                    if entry.name in EXCLUDED_DIR_NAMES or entry.name.endswith(".egg-info"):
                        continue
                    if not self._is_contained(root_real, entry.path):
                        self._traversal_skipped += 1
                        continue
                    child_directories.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False) or not stat.S_ISREG(entry_stat.st_mode):
                    self._traversal_skipped += 1
                    continue
                if not self._is_contained(root_real, entry.path):
                    self._traversal_skipped += 1
                    continue
                relative_path = path.relative_to(root).as_posix()
                if self.is_ignored(relative_path):
                    continue
                if self._encountered_files >= self.max_files:
                    self._mark_truncated("max_files")
                    return
                self._encountered_files += 1
                if not self.is_probably_text(path):
                    continue
                yield path

            directories.extend(reversed(child_directories))

    def _iter_selected_files(self, root: Path, selected_paths: Iterable[str]) -> Iterator[Path]:
        root_real = os.path.realpath(str(root))
        for relative_path in sorted(set(selected_paths)):
            if time.monotonic() >= self._deadline:
                self._mark_truncated("max_duration")
                return
            relative = Path(relative_path)
            if relative.is_absolute() or ".." in relative.parts:
                self._traversal_skipped += 1
                continue
            path = root / relative
            try:
                path_stat = os.lstat(str(path))
            except OSError:
                self._traversal_skipped += 1
                continue
            if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
                self._traversal_skipped += 1
                continue
            if not self._is_contained(root_real, str(path)):
                self._traversal_skipped += 1
                continue
            normalized_path = path.relative_to(root).as_posix()
            if self.is_ignored(normalized_path):
                continue
            if self._encountered_files >= self.max_files:
                self._mark_truncated("max_files")
                return
            self._encountered_files += 1
            if not self.is_probably_text(path):
                continue
            yield path

    def read_snapshot(self, root: Path, path: Path) -> Optional[FileSnapshot]:
        fd: Optional[int] = None
        try:
            before = os.lstat(str(path))
            if not stat.S_ISREG(before.st_mode):
                return None
            root_real = os.path.realpath(str(root))
            if not self._is_contained(root_real, str(path)):
                return None
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(path), flags)
            after = os.fstat(fd)
            if not stat.S_ISREG(after.st_mode):
                return None
            if before.st_dev != after.st_dev or before.st_ino != after.st_ino:
                return None
            # Windows has no O_NOFOLLOW in the stdlib. The lstat, containment,
            # and descriptor checks reduce but cannot eliminate a replacement race.
            with os.fdopen(fd, "rb") as file_handle:
                fd = None
                data = file_handle.read(self.max_file_bytes + 1)
        except OSError:
            return None
        finally:
            if fd is not None:
                os.close(fd)
        if len(data) > self.max_file_bytes:
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
            findings.extend(rule.scan(snapshot, self.evidence_mode))
        for rule in CUSTOM_RULES:
            findings.extend(rule(snapshot, self.evidence_mode))
        return self.dedupe(findings)

    def _limit_reached(self, reason: str, reached: bool) -> bool:
        if reached:
            self._mark_truncated(reason)
            return True
        return False

    def _mark_truncated(self, reason: str) -> None:
        if self._truncation_reason is None:
            self._truncation_reason = reason

    @staticmethod
    def _is_contained(root_real: str, path: str) -> bool:
        try:
            return os.path.commonpath([root_real, os.path.realpath(path)]) == root_real
        except (OSError, ValueError):
            return False

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
            key = (item.rule_id, item.path, item.line, item.match_span)
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
