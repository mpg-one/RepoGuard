import base64
import os
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable, List


_FORBIDDEN = [
    base64.b64decode(value)
    for value in (
        "eG1yaWc=",
        "c3RyYXR1bSt0Y3A=",
        "aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==",
        "fi8uc3NoL2lkX3JzYQ==",
    )
]


def _contained(root: Path, path: Path) -> bool:
    try:
        return os.path.commonpath([str(root), str(path)]) == str(root)
    except ValueError:
        return False


def _unpack_wheel(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(str(archive)) as wheel:
        for member in wheel.infolist():
            target = (destination / member.filename).resolve()
            if not _contained(destination.resolve(), target):
                raise RuntimeError("Unsafe wheel member: {0}".format(member.filename))
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(wheel.read(member))


def _unpack_sdist(archive: Path, destination: Path) -> None:
    with tarfile.open(str(archive), "r:gz") as source:
        for member in source.getmembers():
            target = (destination / member.name).resolve()
            if not _contained(destination.resolve(), target):
                raise RuntimeError("Unsafe sdist member: {0}".format(member.name))
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            extracted = source.extractfile(member)
            if extracted is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(extracted.read())


def _assert_no_literals(roots: Iterable[Path]) -> None:
    violations: List[str] = []
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            data = path.read_bytes().lower()
            for forbidden in _FORBIDDEN:
                if forbidden.lower() in data:
                    violations.append(str(path.relative_to(root)))
                    break
    if violations:
        raise AssertionError("Decoded signature literals found in artifacts: {0}".format(", ".join(sorted(violations))))


def main(arguments: List[str]) -> int:
    if len(arguments) != 1:
        print("usage: check_artifacts.py DIST_DIRECTORY", file=sys.stderr)
        return 2
    dist = Path(arguments[0])
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if not wheels or not sdists:
        raise AssertionError("Expected both wheel and sdist artifacts")
    archives = wheels + sdists
    with tempfile.TemporaryDirectory(prefix="repoguard-artifacts-") as temporary_directory:
        unpacked = []
        for index, archive in enumerate(archives):
            destination = Path(temporary_directory) / str(index)
            destination.mkdir()
            if archive.suffix == ".whl":
                _unpack_wheel(archive, destination)
            else:
                _unpack_sdist(archive, destination)
            unpacked.append(destination)
        _assert_no_literals(unpacked)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
