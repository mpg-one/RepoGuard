# Changelog

## 0.1.1 — Security release

- Fixed repository symlink handling that could cause RepoGuard to read files outside the scan root and echo fragments into reports.
- Added regular-file-only traversal, root containment checks, descriptor identity validation, and `O_NOFOLLOW` protection where supported.
- Changed default evidence to synthetic labels so raw repository content is not emitted unless explicitly requested.
- Added file-count, total-byte, and duration limits with an explicit fail-closed `INCOMPLETE` scan state.
- Restricted remote targets to public `https://github.com/` repository URLs.
- Encoded built-in signatures and moved hostile fixtures to test-time generation so RepoGuard can scan itself without suppressions.
- Refined Python subprocess detection to avoid flagging ordinary argument-list calls.

On Windows, Python's standard library does not expose `O_NOFOLLOW`. RepoGuard uses link classification, containment checks, and pre/post-open descriptor validation there. These checks reduce but cannot fully eliminate a concurrent file-replacement race.
