import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class PreparedTarget:
    original: str
    path: Path
    source: str
    cleanup_path: Optional[Path] = None

    def cleanup(self) -> None:
        if self.cleanup_path and self.cleanup_path.exists():
            shutil.rmtree(self.cleanup_path, ignore_errors=True)


def prepare_target(target: str) -> PreparedTarget:
    local_path = Path(target).expanduser()
    if local_path.exists():
        return PreparedTarget(original=target, path=local_path.resolve(), source="local")
    if is_git_url(target):
        return clone_target(target)
    raise FileNotFoundError("v0.1.1 supports only public https://github.com/ URLs.")


def is_git_url(value: str) -> bool:
    return re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?", value) is not None


def clone_target(url: str) -> PreparedTarget:
    temp_root = Path(tempfile.mkdtemp(prefix="repoguard-"))
    destination = temp_root / "repo"
    env = os.environ.copy()
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "filter.lfs.required=false",
        "clone",
        "--depth",
        "1",
        "--no-tags",
        "--quiet",
        # TODO(v0.x): hardened remote ingestion via --filter=blob:none
        # --no-checkout plus ls-tree size vetting.
        "--",
        url,
        str(destination),
    ]
    try:
        subprocess.run(command, check=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError as exc:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise RuntimeError("git is required to scan remote repositories") from exc
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(temp_root, ignore_errors=True)
        detail = exc.stderr.strip() or exc.stdout.strip() or "unknown git error"
        raise RuntimeError(f"Could not clone target repository: {detail}") from exc
    return PreparedTarget(original=url, path=destination, source="git", cleanup_path=temp_root)
