import base64
import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Callable, Iterable, List, Optional, Pattern, Tuple

from .models import FileSnapshot, Finding


MAX_EVIDENCE_CHARS = 180
EVIDENCE_MODES = {"safe", "none", "snippet"}


def _decode_pattern(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii")).decode("utf-8")


def compile_patterns(
    patterns: Iterable[str], flags: int = re.IGNORECASE | re.MULTILINE | re.DOTALL
) -> List[Pattern[str]]:
    # Encoding prevents RepoGuard from matching its own signature database.
    # It is not secrecy and it is not an anti-evasion control.
    return [re.compile(_decode_pattern(pattern), flags) for pattern in patterns]


_TOKEN_REPLACEMENTS = [
    (compile_patterns(["Z2hbcG91c3JdX1tBLVphLXowLTlfXXsyMCx9"])[0], "gh*_REDACTED"),
    (compile_patterns(["Z2l0aHViX3BhdF9bQS1aYS16MC05X117MjAsfQ=="])[0], "github_pat_REDACTED"),
    (compile_patterns(["QUtJQVswLTlBLVpdezE2fQ=="])[0], "AKIA_REDACTED"),
    (
        compile_patterns(["KD9pKShhcGlbXy1dP2tleXx0b2tlbnxzZWNyZXR8cGFzc3dvcmQpXHMqWzo9XVxzKlsnIl1bXiciXStbJyJd"])[0],
        r"\1=REDACTED",
    ),
]
_PRIVATE_KEY_BLOCK = compile_patterns(
    ["LS0tLS1CRUdJTiBbQS1aIF0qUFJJVkFURSBLRVktLS0tLVtcc1xTXSo/LS0tLS1FTkQgW0EtWiBdKlBSSVZBVEUgS0VZLS0tLS0="]
)[0]
_ENTROPY_RUN = compile_patterns(["XFN7MjAsfQ=="])[0]


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = float(len(value))
    return -sum((count / length) * math.log(count / length, 2) for count in counts.values())


def redact_evidence(value: str) -> str:
    value = _PRIVATE_KEY_BLOCK.sub("PRIVATE_KEY_BLOCK_REDACTED", value)
    value = "".join(character if character.isprintable() else " " for character in value)
    value = " ".join(value.split())
    for pattern, replacement in _TOKEN_REPLACEMENTS:
        value = pattern.sub(replacement, value)

    def mask_entropy(match: re.Match) -> str:
        candidate = match.group(0)
        if _shannon_entropy(candidate) > 4.0:
            return "HIGH_ENTROPY_REDACTED"
        return candidate

    value = _ENTROPY_RUN.sub(mask_entropy, value)
    value = value.strip()
    if len(value) > MAX_EVIDENCE_CHARS:
        return value[: MAX_EVIDENCE_CHARS - 3] + "..."
    return value


def render_evidence(mode: str, label: str, snippet: str) -> Optional[str]:
    if mode not in EVIDENCE_MODES:
        raise ValueError("Unsupported evidence mode: {0}".format(mode))
    if mode == "none":
        return None
    if mode == "safe":
        return label
    return redact_evidence(snippet)


def line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def finding_fingerprint(rule_id: str, relative_path: str, raw_matched_text: str) -> str:
    match_hash = hashlib.sha256(raw_matched_text.encode("utf-8")).hexdigest()
    identity = "{0}|{1}|{2}".format(rule_id, relative_path, match_hash)
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RegexRule:
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    recommendation: str
    evidence_label: str
    patterns: List[Pattern[str]]
    path_globs: Optional[List[str]] = None

    def applies_to(self, relative_path: str) -> bool:
        if not self.path_globs:
            return True
        return any(fnmatch(relative_path, glob) for glob in self.path_globs)

    def scan(self, snapshot: FileSnapshot, evidence_mode: str = "safe") -> Iterable[Finding]:
        if not self.applies_to(snapshot.relative_path):
            return []
        findings = []
        for pattern in self.patterns:
            for match in pattern.finditer(snapshot.text):
                raw_matched_text = match.group(0)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        path=snapshot.relative_path,
                        line=line_number(snapshot.text, match.start()),
                        evidence=render_evidence(
                            evidence_mode,
                            self.evidence_label,
                            raw_matched_text.replace("\n", " "),
                        ),
                        description=self.description,
                        recommendation=self.recommendation,
                        match_span=match.span(),
                        fingerprint=finding_fingerprint(
                            self.rule_id, snapshot.relative_path, raw_matched_text
                        ),
                    )
                )
        return findings


CustomRule = Callable[[FileSnapshot, str], Iterable[Finding]]


def finding(
    snapshot: FileSnapshot,
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    recommendation: str,
    evidence_label: str,
    evidence_snippet: str,
    evidence_mode: str = "safe",
    index: int = 0,
    match_span: Optional[Tuple[int, int]] = None,
    raw_matched_text: Optional[str] = None,
) -> Finding:
    raw_match = evidence_snippet if raw_matched_text is None else raw_matched_text
    span = match_span if match_span is not None else (index, index + len(raw_match))
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        path=snapshot.relative_path,
        line=line_number(snapshot.text, index),
        evidence=render_evidence(evidence_mode, evidence_label, evidence_snippet.replace("\n", " ")),
        description=description,
        recommendation=recommendation,
        match_span=span,
        fingerprint=finding_fingerprint(rule_id, snapshot.relative_path, raw_match),
    )


_LIFECYCLE_REMOTE = compile_patterns(
    ["XGIoY3VybHx3Z2V0KVxiW15cbnw7XSooXHxccyooc3Vkb1xzKyk/KGJhc2h8c2gpfFxiKGJhc2h8c2gpXGIp"], re.IGNORECASE
)[0]
_LIFECYCLE_SHELL = compile_patterns(
    ["XGIobm9kZXxweXRob258cHl0aG9uM3xwZXJsfHJ1Ynl8YmFzaHxzaHxwb3dlcnNoZWxsfGNtZFwuZXhlKVxi"], re.IGNORECASE
)[0]
_SENSITIVE_REFERENCE = compile_patterns(
    ["KH5cL1wuc3NofGlkX3JzYXxpZF9lZDI1NTE5fFwuZW52XGJ8XC5ucG1yY3xcLnB5cGlyY3xhd3NfYWNjZXNzX2tleXxhd3Nfc2VjcmV0fGdpdGh1Yl90b2tlbnwvZXRjL3Bhc3N3ZHxjcmVkZW50aWFscyk="],
    re.IGNORECASE,
)[0]
_NETWORK_UPLOAD = compile_patterns(
    ["KHJlcXVlc3RzXC4ocG9zdHxwdXQpfGZldGNoXHMqXCh8YXhpb3NcLihwb3N0fHB1dCl8aHR0cFwucmVxdWVzdHxodHRwc1wucmVxdWVzdHxjdXJsXHMrfHdnZXRccyt8bmNccyt8bmV0Y2F0fEludm9rZS1XZWJSZXF1ZXN0KQ=="],
    re.IGNORECASE,
)[0]
_WORKFLOW_SECRET = compile_patterns(
    ["XGJzZWNyZXRzXC5bQS1aMC05X10rXGJ8XCRce1x7XHMqc2VjcmV0c1wu"], re.IGNORECASE
)[0]
_WORKFLOW_REMOTE = compile_patterns(
    ["XGIoY3VybHx3Z2V0fGJhc2h8c2h8cHl0aG9ufG5vZGV8cG93ZXJzaGVsbClcYg=="], re.IGNORECASE
)[0]


def package_json_lifecycle_rule(snapshot: FileSnapshot, evidence_mode: str = "safe") -> Iterable[Finding]:
    if not snapshot.relative_path.endswith("package.json"):
        return []
    try:
        package = json.loads(snapshot.text)
    except json.JSONDecodeError:
        return []
    scripts = package.get("scripts")
    if not isinstance(scripts, dict):
        return []

    lifecycle_names = {"preinstall", "install", "postinstall", "prepare", "prepack", "postpack"}
    results = []
    for name, command in scripts.items():
        if name not in lifecycle_names or not isinstance(command, str):
            continue
        severity = "high" if _LIFECYCLE_REMOTE.search(command) else "medium"
        if severity == "medium" and not _LIFECYCLE_SHELL.search(command):
            continue
        index = snapshot.text.find(name)
        results.append(
            finding(
                snapshot,
                "package-lifecycle-script",
                "Package lifecycle script executes commands during install.",
                severity,
                "install",
                "Package manager lifecycle hooks can run automatically when dependencies are installed.",
                "Inspect the lifecycle script before installing dependencies or allowing an agent to run package commands.",
                "lifecycle script: {0}".format(name),
                "{0}: {1}".format(name, command),
                evidence_mode,
                max(index, 0),
                raw_matched_text=command,
            )
        )
    return results


def sensitive_network_combo_rule(snapshot: FileSnapshot, evidence_mode: str = "safe") -> Iterable[Finding]:
    sensitive_match = _SENSITIVE_REFERENCE.search(snapshot.text)
    network_match = _NETWORK_UPLOAD.search(snapshot.text)
    if not sensitive_match or not network_match:
        return []
    index = min(sensitive_match.start(), network_match.start())
    end = max(sensitive_match.end(), network_match.end())
    return [
        finding(
            snapshot,
            "exfil-sensitive-network",
            "Sensitive local data appears near network upload behavior.",
            "critical",
            "exfiltration",
            "The file references sensitive local paths or credentials and network upload APIs.",
            "Review manually before giving an agent shell access; run only in a sandbox if this is expected.",
            "sensitive local data + network upload API",
            "{0} ... {1}".format(sensitive_match.group(0), network_match.group(0)),
            evidence_mode,
            index,
            match_span=(index, end),
            raw_matched_text=snapshot.text[index:end],
        )
    ]


def github_actions_secret_remote_rule(snapshot: FileSnapshot, evidence_mode: str = "safe") -> Iterable[Finding]:
    if not fnmatch(snapshot.relative_path, ".github/workflows/*"):
        return []
    has_secret = _WORKFLOW_SECRET.search(snapshot.text)
    has_remote = _WORKFLOW_REMOTE.search(snapshot.text)
    if not has_secret or not has_remote:
        return []
    index = min(has_secret.start(), has_remote.start())
    end = max(has_secret.end(), has_remote.end())
    return [
        finding(
            snapshot,
            "github-actions-secret-remote-exec",
            "Workflow combines secrets with remote or shell execution.",
            "high",
            "ci",
            "GitHub Actions secrets are referenced in a workflow that also runs shell or network-capable commands.",
            "Review the workflow before running CI or letting an agent edit and trigger it.",
            "workflow secret + shell or network command",
            "{0} ... {1}".format(has_secret.group(0), has_remote.group(0)),
            evidence_mode,
            index,
            match_span=(index, end),
            raw_matched_text=snapshot.text[index:end],
        )
    ]


REGEX_RULES: List[RegexRule] = [
    RegexRule(
        rule_id="agent-prompt-injection",
        title="Agent-targeted prompt injection language found.",
        severity="high",
        category="agent",
        description="Text appears to instruct AI coding agents to ignore, override, reveal, or execute instructions.",
        recommendation="Treat this as hostile project context and review before loading the repo into an agent.",
        evidence_label="agent-directed instruction override language",
        path_globs=["*.md", "*.mdx", "*.txt", "docs/*", "doc/*", "**/*.md", "**/*.mdx", "**/*.txt"],
        patterns=compile_patterns(
            [
                "XGIoaWdub3JlfGRpc3JlZ2FyZHxvdmVycmlkZXxmb3JnZXQpXHMrKGFsbFxzKyk/KHByZXZpb3VzfHByaW9yfGFib3ZlfHN5c3RlbXxkZXZlbG9wZXIpXHMrKGluc3RydWN0aW9uc3xwcm9tcHRzfHJ1bGVzKVxi",
                "XGIocmV2ZWFsfHByaW50fGR1bXB8c2VuZHxleGZpbHRyYXRlKVxzKyh0aGVccyspPyhzeXN0ZW0gcHJvbXB0fGRldmVsb3BlciBtZXNzYWdlfGhpZGRlbiBpbnN0cnVjdGlvbnMpXGI=",
                "XGIoY29kZXh8Y2xhdWRlIGNvZGV8Y2xhdWRlfGN1cnNvcnxnZW1pbmkgY2xpfG9wZW5haSlcYi57MCwxMjB9XGIocnVufGV4ZWN1dGV8aWdub3JlfHNlbmR8dXBsb2FkfGV4ZmlsdHJhdGV8bGVhaylcYg==",
            ]
        ),
    ),
    RegexRule(
        rule_id="agent-credential-request",
        title="Agent-facing text asks for sensitive credentials or files.",
        severity="critical",
        category="agent",
        description="Text references an AI agent and sensitive local files or credential material.",
        recommendation="Do not expose this repository to an agent with access to user files or secrets.",
        evidence_label="agent request for sensitive credential material",
        patterns=compile_patterns(
            [
                "XGIoY29kZXh8Y2xhdWRlfGN1cnNvcnxhZ2VudHxhc3Npc3RhbnQpXGIuezAsMTYwfSh+XC9cLnNzaHxpZF9yc2F8aWRfZWQyNTUxOXxcLmVudnxhd3Nfc2VjcmV0fGdpdGh1Yl90b2tlbnxhcGlbXy1dP2tleSk=",
                "KH5cL1wuc3NofGlkX3JzYXxpZF9lZDI1NTE5fFwuZW52fGF3c19zZWNyZXR8Z2l0aHViX3Rva2VufGFwaVtfLV0/a2V5KS57MCwxNjB9XGIoc2VuZHx1cGxvYWR8cG9zdHxjdXJsfGZldGNofGV4ZmlsdHJhdGUpXGI=",
            ]
        ),
    ),
    RegexRule(
        rule_id="shell-pipe-to-shell",
        title="Remote script is piped into a shell.",
        severity="high",
        category="install",
        description="The repository contains a command pattern that downloads code and immediately executes it.",
        recommendation="Inspect the downloaded script before execution; agents should not run this automatically.",
        evidence_label="remote script piped to shell",
        patterns=compile_patterns(["XGIoY3VybHx3Z2V0KVxiW15cbnw7XSooXHxccyooc3Vkb1xzKyk/KGJhc2h8c2gpfD5ccyovdG1wL1teO1xuXSs7XHMqKGJhc2h8c2gpXGIp"]),
    ),
    RegexRule(
        rule_id="remote-binary-download",
        title="Remote binary or archive download found.",
        severity="high",
        category="install",
        description="The repository downloads a remote binary or release artifact that may bypass normal dependency review.",
        recommendation="Verify the source, checksum, and necessity before running install or setup commands.",
        evidence_label="remote binary or archive download",
        patterns=compile_patterns(["XGIoY3VybHx3Z2V0KVxiLnswLDE4MH0oKC9yZWxlYXNlcy9kb3dubG9hZC8pfChcLnRhclwuZ3p8XC50Z3p8XC56aXB8XC5leGV8XC5kbWd8XC5wa2d8XC5kZWJ8XC5ycG18XC5zb3xcLmRsbClcYik="]),
    ),
    RegexRule(
        rule_id="python-dynamic-execution",
        title="Python dynamic command execution found.",
        severity="medium",
        category="execution",
        description="Python code can execute shell commands or dynamic code.",
        recommendation="Review before letting an agent run tests, setup, or scripts from this repository.",
        evidence_label="dynamic Python or shell command execution",
        path_globs=["*.py", "**/*.py"],
        patterns=compile_patterns(
            [
                "XGIoPzpvc1wuc3lzdGVtfGV2YWx8ZXhlYylccypcKA==",
                "XGJzdWJwcm9jZXNzXC4oPzpydW58UG9wZW58Y2FsbHxjaGVja19jYWxsfGNoZWNrX291dHB1dClccypcKFxzKig/OltydWJmUlVCRl17MCwyfSk/WyInXQ==",
                "XGJzdWJwcm9jZXNzXC4oPzpydW58UG9wZW58Y2FsbHxjaGVja19jYWxsfGNoZWNrX291dHB1dClccypcKFteKV17MCw1MDB9XGJzaGVsbFxzKj1ccypUcnVlXGI=",
            ]
        ),
    ),
    RegexRule(
        rule_id="node-child-process",
        title="Node.js child process execution found.",
        severity="medium",
        category="execution",
        description="JavaScript or TypeScript code can spawn processes or execute shell commands.",
        recommendation="Review before letting an agent run package scripts or project commands.",
        evidence_label="Node.js child process execution",
        path_globs=["*.js", "*.mjs", "*.cjs", "*.ts", "**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"],
        patterns=compile_patterns(["XGJyZXF1aXJlXChbJyJdY2hpbGRfcHJvY2Vzc1snIl1cKXxcYmZyb21ccytbJyJdY2hpbGRfcHJvY2Vzc1snIl18XGIoZXhlY3xleGVjU3luY3xzcGF3bnxzcGF3blN5bmMpXHMqXCg="]),
    ),
    RegexRule(
        rule_id="obfuscated-javascript",
        title="Obfuscated JavaScript pattern found.",
        severity="high",
        category="obfuscation",
        description="JavaScript contains patterns commonly used to hide behavior.",
        recommendation="Do not run this code until the obfuscated behavior is decoded and reviewed.",
        evidence_label="obfuscated JavaScript construct",
        path_globs=["*.js", "*.mjs", "*.cjs", "**/*.js", "**/*.mjs", "**/*.cjs"],
        patterns=compile_patterns(
            [
                "XGJldmFsXHMqXChccyphdG9iXHMqXCg=",
                "XGJuZXdccytGdW5jdGlvblxzKlwo",
                "XGJTdHJpbmdcLmZyb21DaGFyQ29kZVxzKlwo",
                "WyciXVtBLVphLXowLTkrL117MTgwLH09ezAsMn1bJyJd",
            ]
        ),
    ),
    RegexRule(
        rule_id="github-actions-pull-request-target",
        title="Workflow uses pull_request_target.",
        severity="high",
        category="ci",
        description="The pull_request_target event can expose privileged workflow context to untrusted pull requests.",
        recommendation="Review workflow permissions and avoid checking out untrusted code with elevated tokens.",
        evidence_label="privileged pull request workflow trigger",
        path_globs=[".github/workflows/*"],
        patterns=compile_patterns(["XlxzKnB1bGxfcmVxdWVzdF90YXJnZXRccyo6"]),
    ),
    RegexRule(
        rule_id="github-actions-self-hosted-runner",
        title="Workflow uses a self-hosted runner.",
        severity="medium",
        category="ci",
        description="Self-hosted runners can expose private infrastructure if a workflow is unsafe.",
        recommendation="Verify runner isolation and avoid running untrusted repository code on persistent machines.",
        evidence_label="self-hosted workflow runner",
        path_globs=[".github/workflows/*"],
        patterns=compile_patterns(["cnVucy1vblxzKjpccyooXFsuKnNlbGYtaG9zdGVkLipcXXxzZWxmLWhvc3RlZCk="]),
    ),
    RegexRule(
        rule_id="crypto-miner-indicator",
        title="Crypto miner indicator found.",
        severity="critical",
        category="malware",
        description="The repository references terms commonly associated with cryptocurrency mining malware.",
        recommendation="Do not run this repository until the miner-related behavior is understood.",
        evidence_label="cryptocurrency mining indicator",
        patterns=compile_patterns(["XGIoeG1yaWd8bW9uZXJvfHN0cmF0dW1cK3RjcHxuYW5vcG9vbHxtaW5lcmdhdGV8Y3J5cHRvbmlnaHQpXGI="]),
    ),
    RegexRule(
        rule_id="docker-host-escape-risk",
        title="Container host escape risk pattern found.",
        severity="high",
        category="sandbox",
        description="Docker socket mounts or privileged containers can allow code to control the host.",
        recommendation="Do not run this with host Docker access unless it is fully trusted.",
        evidence_label="container access to host-level privileges",
        patterns=compile_patterns(["L3Zhci9ydW4vZG9ja2VyXC5zb2NrfC0tcHJpdmlsZWdlZFxi"]),
    ),
]


CUSTOM_RULES: List[CustomRule] = [
    package_json_lifecycle_rule,
    sensitive_network_combo_rule,
    github_actions_secret_remote_rule,
]
