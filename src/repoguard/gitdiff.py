import subprocess
from pathlib import Path
from typing import List


def diff_paths(root: Path, ref: str) -> List[str]:
    if ref.startswith("-"):
        raise ValueError("Invalid --diff ref: {0}".format(ref))
    changed = _git(
        root,
        ["diff", "--name-only", "--diff-filter=d", ref, "--", "."],
        "Could not calculate diff for {0}".format(ref),
    )
    untracked = _git(
        root,
        ["ls-files", "--others", "--exclude-standard"],
        "Could not list untracked files",
    )
    return sorted(set(changed.splitlines()) | set(untracked.splitlines()))


def _git(root: Path, arguments: List[str], error_prefix: str) -> str:
    try:
        result = subprocess.run(
            ["git"] + arguments,
            cwd=str(root),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git is required for --diff scans") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or "unknown git error"
        raise RuntimeError("{0}: {1}".format(error_prefix, detail)) from exc
    return result.stdout
