# RepoGuard

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3776AB.svg)](pyproject.toml)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](https://github.com/mpg-one/RepoGuard)

**Scan before you agent.**

RepoGuard is a local-first static scanner that checks an unknown repository for risks targeting AI coding agents such as Codex, Claude Code, Cursor, Gemini CLI, and similar tools.

Made by **MPG ONE LLC**.

```bash
python3 -m pip install git+https://github.com/mpg-one/RepoGuard.git
repoguard scan https://github.com/user/repository
```

RepoGuard analyzes the repository without running its code, installing its dependencies, or executing its setup scripts. No API key is required.

## Why RepoGuard

AI coding agents do more than read source code. They can follow repository instructions, run terminal commands, install packages, access local files, use credentials, and trigger workflows.

A repository that looks ordinary to a human can contain instructions or automation designed to manipulate an agent. RepoGuard gives you a fast preflight report before the agent receives access.

| Capability | Included |
| --- | --- |
| Scan local directories | Yes |
| Scan GitHub and Git repository URLs | Yes |
| Detect agent-focused prompt injection | Yes |
| Inspect install scripts and package hooks | Yes |
| Inspect risky GitHub Actions patterns | Yes |
| Correlate sensitive-file access with network upload behavior | Yes |
| Text, JSON, and SARIF reports | Yes |
| CI-friendly exit-code gating | Yes |
| Execute repository code | Never |
| Upload repository contents for analysis | Never |

## Quick Start

### Install from GitHub

```bash
python3 -m pip install git+https://github.com/mpg-one/RepoGuard.git
```

### Scan a local repository

```bash
repoguard scan ./project
```

### Scan a remote repository

```bash
repoguard scan https://github.com/user/repository
```

Remote repositories are shallow-cloned into a temporary directory with Git hooks and LFS downloads disabled. The temporary copy is removed after the scan.

### Run without installing

From a local RepoGuard clone:

```bash
PYTHONPATH=src python3 -m repoguard scan ./project
```

## What It Detects

| Risk category | Examples |
| --- | --- |
| Agent manipulation | Instructions telling Codex, Claude Code, Cursor, or another agent to ignore rules, reveal prompts, or execute commands |
| Credential targeting | Requests involving `.env`, SSH keys, API keys, tokens, cloud credentials, or other sensitive local files |
| Dangerous installation | `curl | bash`, `wget | sh`, remote binary downloads, and package lifecycle hooks |
| Data exfiltration | Sensitive-file references combined with network upload behavior |
| Risky automation | `pull_request_target`, secrets combined with shell execution, and self-hosted GitHub Actions runners |
| Hidden execution | Python dynamic execution, Node.js child processes, and obfuscated JavaScript |
| Malware indicators | Crypto-mining terms and suspicious encoded payload patterns |
| Sandbox escape risk | Docker socket mounts and privileged container execution |

Every finding includes:

- severity and rule identifier
- file path and line number
- redacted evidence
- explanation of the risk
- recommended next action

## Example Result

```text
RepoGuard by MPG ONE LLC
========================
Version: 0.1.0
Target: suspicious-repository
Source: local
Risk: Critical
Score: 100/100

Findings:
  - CRITICAL agent-credential-request README.md:3
    Agent-facing text asks for sensitive credentials or files.
    Fix: Do not expose this repository to an agent with access to user files or secrets.

  - HIGH shell-pipe-to-shell install.sh:2
    Remote script is piped into a shell.
    Fix: Inspect the downloaded script before execution; agents should not run this automatically.

Recommendation:
  Do not load this repository into an AI coding agent without isolation and manual security review.
```

## See It In Action

<p align="center">
  <img src="assets/screenshots/critical-scan.svg" alt="RepoGuard critical repository scan" width="32%">
  <img src="assets/screenshots/clean-json.svg" alt="RepoGuard JSON output" width="32%">
  <img src="assets/screenshots/ci-gate.svg" alt="RepoGuard CI gate" width="32%">
</p>

## Output Formats

Human-readable terminal report:

```bash
repoguard scan .
```

JSON for scripts, agents, and other tools:

```bash
repoguard scan . --format json
```

SARIF for security pipelines and code-scanning systems:

```bash
repoguard scan . --format sarif --output repoguard.sarif
```

## Use It Before an AI Agent

Run RepoGuard before opening an unknown project with an agent:

```bash
repoguard scan https://github.com/user/repository --fail-on high
```

If RepoGuard exits successfully, review any remaining low or medium findings before continuing. A high or critical result exits with status `2` when `--fail-on high` is used.

```text
Unknown repository
        |
        v
RepoGuard static scan
        |
        v
Review risk report
        |
        v
Allow, sandbox, or reject agent access
```

## CI Gate

Fail automation when the final risk level reaches a chosen threshold:

```bash
repoguard scan . --fail-on high
```

Available thresholds:

- `low`
- `medium`
- `high`
- `critical`

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Scan completed and the configured threshold was not reached |
| `1` | RepoGuard could not complete the scan |
| `2` | The configured `--fail-on` threshold was reached |

## Ignore Policy

Use an explicit ignore file when scanning a trusted project with known test fixtures or generated content:

```bash
repoguard scan . --ignore-file .repoguardignore
```

RepoGuard does not automatically trust ignore files shipped by the repository being scanned. Otherwise, a hostile repository could use its own ignore configuration to hide risky files from the scanner.

## Integrations

Available today:

- command-line scanning for local paths and Git URLs
- JSON output for scripts and agent tooling
- SARIF output for security pipelines
- threshold-based exit codes for automation

Planned integrations:

- MCP server for MCP-compatible clients
- globally installed Codex and Claude Code skills
- GitHub Action for repository and pull-request scanning
- commit-aware trust receipts and changed-file scanning

The CLI is the working product today. Planned integrations will use the same scanner engine and rules.

## Security Model

RepoGuard is deliberately static and local-first:

- it does not execute repository code
- it does not install repository dependencies
- it does not run setup or package scripts
- it does not require an LLM or API key
- it does not upload repository contents for analysis
- it redacts common credential formats from displayed evidence

Remote scanning requires Git and network access only to download the requested repository.

## Limitations

RepoGuard is a focused pre-agent risk scanner. It is not a full antivirus engine, dependency vulnerability scanner, malware sandbox, or guarantee that a repository is safe.

Static rules can produce false positives and cannot detect every multi-stage or environment-dependent attack. Treat a clean report as one useful security signal, not unlimited permission for an agent.

## Development

Clone the repository and run the test suite:

```bash
git clone https://github.com/mpg-one/RepoGuard.git
cd RepoGuard
PYTHONPATH=src python3 -m unittest discover -s tests
```

Scan the included suspicious fixture:

```bash
PYTHONPATH=src python3 -m repoguard scan tests/fixtures/suspicious-repo
```

Scan RepoGuard while excluding its intentionally suspicious test signatures:

```bash
PYTHONPATH=src python3 -m repoguard scan . --ignore-file .repoguardignore
```

Contributions, new detection rules, adversarial fixtures, and false-positive reports are welcome through [GitHub Issues](https://github.com/mpg-one/RepoGuard/issues).

## License And Trademark

Copyright 2026 MPG ONE LLC.

RepoGuard is open-source software licensed under the [Apache License 2.0](LICENSE). You may use, modify, and distribute it under that license. See [TRADEMARKS.md](TRADEMARKS.md) for the RepoGuard and MPG ONE branding policy.
