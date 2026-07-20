# Changelog

## 0.2.0 — Noise control

- Added explicit baseline files that suppress accepted fingerprints from scoring and default output. Baselines are loaded only with `--baseline`; RepoGuard never trusts or auto-loads a baseline shipped by the scanned repository.
- Added `--diff REF` for scanning changed and untracked files in local Git repositories through the same hardened file pipeline as full scans.
- Made `repoguard` and `repoguard scan` default to the current directory when no target is provided.
- Added `-q` / `--quiet` for a one-line verdict suitable for frequent local checks.
- Made finding deduplication independent of evidence mode by using internal match spans instead of rendered evidence.
- Added `.DS_Store` to the project ignore list.

## 0.1.1 — Security release

- Fixed repository symlink handling that could cause RepoGuard to read files outside the scan root and echo fragments into reports.
- Added regular-file-only traversal, root containment checks, descriptor identity validation, and `O_NOFOLLOW` protection where supported.
- Changed default evidence to synthetic labels so raw repository content is not emitted unless explicitly requested.
- Added file-count, total-byte, and duration limits with an explicit fail-closed `INCOMPLETE` scan state.
- Restricted remote targets to public `https://github.com/` repository URLs.
- Encoded built-in signatures and moved hostile fixtures to test-time generation so RepoGuard can scan itself without suppressions.
- Refined Python subprocess detection to avoid flagging ordinary argument-list calls.

On Windows, Python's standard library does not expose `O_NOFOLLOW`. RepoGuard uses link classification, containment checks, and pre/post-open descriptor validation there. These checks reduce but cannot fully eliminate a concurrent file-replacement race.
