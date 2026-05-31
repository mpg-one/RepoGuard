# RepoGuard

**Scan before you agent.**

RepoGuard is a free-to-use static repository scanner for AI coding agents such as Codex, Claude Code, Cursor, Gemini CLI, and similar tools.

Made by **MPG ONE LLC**.

RepoGuard is free for end users, but it is not an open-source license. You may use it for free, but you may not copy, rename, rebrand, redistribute, sell, or publish modified versions without written permission from MPG ONE LLC.

## Why

AI coding agents can read project files, follow instructions in docs, run commands, install dependencies, and edit code. That creates a new risk category: a repository may be safe-looking to a human but hostile to an autonomous coding agent.

RepoGuard checks a repository before you give it to an agent.

It looks for risks like:

- prompt injection aimed at AI coding agents
- dangerous install scripts such as `curl | bash`
- package lifecycle scripts that run shell commands
- sensitive-file access combined with network exfiltration
- suspicious GitHub Actions workflows
- obfuscated JavaScript
- crypto miner indicators
- Docker socket and privileged container usage

RepoGuard does **static analysis only**. It does not run repository code, install dependencies, or execute setup scripts.

## Install

Directly from GitHub:

```bash
python3 -m pip install git+https://github.com/mpg-one/RepoGuard.git
```

Or from a local clone of this repository:

```bash
python3 -m pip install .
```

Then run:

```bash
repoguard scan .
```

You can also run it without installing:

```bash
PYTHONPATH=src python3 -m repoguard scan .
```

## Scan A GitHub Repository

```bash
repoguard scan https://github.com/user/repo
```

RepoGuard clones the repository into a temporary directory, scans it, and removes the temporary copy when finished.

## Output Formats

Human-readable report:

```bash
repoguard scan .
```

JSON report:

```bash
repoguard scan . --format json
```

SARIF report for security tooling:

```bash
repoguard scan . --format sarif --output repoguard.sarif
```

Use an explicit ignore file:

```bash
repoguard scan . --ignore-file .repoguardignore
```

RepoGuard does not automatically trust ignore files from scanned repositories. This is intentional: an unknown hostile repo should not be able to hide files from the scanner by shipping its own ignore config.

## CI Gate

Fail a CI job when the risk level reaches a threshold:

```bash
repoguard scan . --fail-on high
```

Thresholds are:

- `low`
- `medium`
- `high`
- `critical`

## Example

```txt
RepoGuard by MPG ONE LLC
Target: https://github.com/user/repo
Risk: High
Score: 72/100

Findings:
- HIGH agent-prompt-injection README.md:12
  Agent-targeted prompt injection language found.

- CRITICAL exfil-sensitive-network scripts/setup.py:31
  Sensitive local files and network upload behavior appear in the same file.

Recommendation:
Do not load this repository into an AI coding agent without sandboxing and manual review.
```

## What RepoGuard Is Not

RepoGuard is not a full antivirus engine, vulnerability scanner, or guarantee that a repository is safe. It is a fast pre-agent risk check designed to catch patterns that matter when an AI coding agent is about to inspect or operate on unknown code.

## Development

Run tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Run the CLI against the suspicious fixture:

```bash
PYTHONPATH=src python3 -m repoguard scan tests/fixtures/suspicious-repo
```

Scan this repository while ignoring test signatures:

```bash
PYTHONPATH=src python3 -m repoguard scan . --ignore-file .repoguardignore
```

## License

Copyright (c) 2026 MPG ONE LLC. All rights reserved.

RepoGuard is free to use under the RepoGuard Free Use License. Redistribution, copying, rebranding, white-labeling, selling, publishing modified versions, or representing RepoGuard as your own product is not allowed without written permission from MPG ONE LLC.
