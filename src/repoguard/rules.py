import json
import re
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Callable, Iterable, List, Optional, Pattern

from .models import FileSnapshot, Finding


MAX_EVIDENCE_CHARS = 180


def redact_evidence(value: str) -> str:
    value = value.strip()
    replacements = [
        (r"gh[pousr]_[A-Za-z0-9_]{20,}", "gh*_REDACTED"),
        (r"github_pat_[A-Za-z0-9_]{20,}", "github_pat_REDACTED"),
        (r"AKIA[0-9A-Z]{16}", "AKIA_REDACTED"),
        (r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"][^'\"]+['\"]", r"\1=REDACTED"),
        (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "PRIVATE_KEY_REDACTED"),
    ]
    for pattern, replacement in replacements:
        value = re.sub(pattern, replacement, value)
    if len(value) > MAX_EVIDENCE_CHARS:
        return value[: MAX_EVIDENCE_CHARS - 3] + "..."
    return value


def line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


@dataclass(frozen=True)
class RegexRule:
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    recommendation: str
    patterns: List[Pattern[str]]
    path_globs: Optional[List[str]] = None

    def applies_to(self, relative_path: str) -> bool:
        if not self.path_globs:
            return True
        return any(fnmatch(relative_path, glob) for glob in self.path_globs)

    def scan(self, snapshot: FileSnapshot) -> Iterable[Finding]:
        if not self.applies_to(snapshot.relative_path):
            return []
        findings = []
        for pattern in self.patterns:
            for match in pattern.finditer(snapshot.text):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        path=snapshot.relative_path,
                        line=line_number(snapshot.text, match.start()),
                        evidence=redact_evidence(match.group(0).replace("\n", " ")),
                        description=self.description,
                        recommendation=self.recommendation,
                    )
                )
        return findings


CustomRule = Callable[[FileSnapshot], Iterable[Finding]]


def compile_patterns(patterns: Iterable[str]) -> List[Pattern[str]]:
    return [re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL) for pattern in patterns]


def finding(
    snapshot: FileSnapshot,
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    recommendation: str,
    evidence: str,
    index: int = 0,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        path=snapshot.relative_path,
        line=line_number(snapshot.text, index),
        evidence=redact_evidence(evidence.replace("\n", " ")),
        description=description,
        recommendation=recommendation,
    )


def package_json_lifecycle_rule(snapshot: FileSnapshot) -> Iterable[Finding]:
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
    remote_execution = re.compile(r"\b(curl|wget)\b[^\n|;]*(\|\s*(sudo\s+)?(bash|sh)|\b(bash|sh)\b)", re.I)
    shell_execution = re.compile(r"\b(node|python|python3|perl|ruby|bash|sh|powershell|cmd\.exe)\b", re.I)
    results = []
    for name, command in scripts.items():
        if name not in lifecycle_names or not isinstance(command, str):
            continue
        severity = "high" if remote_execution.search(command) else "medium"
        if severity == "medium" and not shell_execution.search(command):
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
                f"{name}: {command}",
                max(index, 0),
            )
        )
    return results


def sensitive_network_combo_rule(snapshot: FileSnapshot) -> Iterable[Finding]:
    sensitive = re.compile(
        r"(~\/\.ssh|id_rsa|id_ed25519|\.env\b|\.npmrc|\.pypirc|aws_access_key|aws_secret|github_token|/etc/passwd|credentials)",
        re.I,
    )
    network = re.compile(
        r"(requests\.(post|put)|fetch\s*\(|axios\.(post|put)|http\.request|https\.request|curl\s+|wget\s+|nc\s+|netcat|Invoke-WebRequest)",
        re.I,
    )
    sensitive_match = sensitive.search(snapshot.text)
    network_match = network.search(snapshot.text)
    if not sensitive_match or not network_match:
        return []
    index = min(sensitive_match.start(), network_match.start())
    evidence = f"{sensitive_match.group(0)} ... {network_match.group(0)}"
    return [
        finding(
            snapshot,
            "exfil-sensitive-network",
            "Sensitive local data appears near network upload behavior.",
            "critical",
            "exfiltration",
            "The file references sensitive local paths or credentials and network upload APIs.",
            "Review manually before giving an agent shell access; run only in a sandbox if this is expected.",
            evidence,
            index,
        )
    ]


def github_actions_secret_remote_rule(snapshot: FileSnapshot) -> Iterable[Finding]:
    if not fnmatch(snapshot.relative_path, ".github/workflows/*"):
        return []
    has_secret = re.search(r"\bsecrets\.[A-Z0-9_]+\b|\$\{\{\s*secrets\.", snapshot.text, re.I)
    has_remote = re.search(r"\b(curl|wget|bash|sh|python|node|powershell)\b", snapshot.text, re.I)
    if not has_secret or not has_remote:
        return []
    index = min(has_secret.start(), has_remote.start())
    return [
        finding(
            snapshot,
            "github-actions-secret-remote-exec",
            "Workflow combines secrets with remote or shell execution.",
            "high",
            "ci",
            "GitHub Actions secrets are referenced in a workflow that also runs shell or network-capable commands.",
            "Review the workflow before running CI or letting an agent edit and trigger it.",
            f"{has_secret.group(0)} ... {has_remote.group(0)}",
            index,
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
        path_globs=["*.md", "*.mdx", "*.txt", "docs/*", "doc/*", "**/*.md", "**/*.mdx", "**/*.txt"],
        patterns=compile_patterns(
            [
                r"\b(ignore|disregard|override|forget)\s+(all\s+)?(previous|prior|above|system|developer)\s+(instructions|prompts|rules)\b",
                r"\b(reveal|print|dump|send|exfiltrate)\s+(the\s+)?(system prompt|developer message|hidden instructions)\b",
                r"\b(codex|claude code|claude|cursor|gemini cli|openai)\b.{0,120}\b(run|execute|ignore|send|upload|exfiltrate|leak)\b",
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
        patterns=compile_patterns(
            [
                r"\b(codex|claude|cursor|agent|assistant)\b.{0,160}(~\/\.ssh|id_rsa|id_ed25519|\.env|aws_secret|github_token|api[_-]?key)",
                r"(~\/\.ssh|id_rsa|id_ed25519|\.env|aws_secret|github_token|api[_-]?key).{0,160}\b(send|upload|post|curl|fetch|exfiltrate)\b",
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
        patterns=compile_patterns(
            [
                r"\b(curl|wget)\b[^\n|;]*(\|\s*(sudo\s+)?(bash|sh)|>\s*/tmp/[^;\n]+;\s*(bash|sh)\b)",
            ]
        ),
    ),
    RegexRule(
        rule_id="remote-binary-download",
        title="Remote binary or archive download found.",
        severity="high",
        category="install",
        description="The repository downloads a remote binary or release artifact that may bypass normal dependency review.",
        recommendation="Verify the source, checksum, and necessity before running install or setup commands.",
        patterns=compile_patterns(
            [
                r"\b(curl|wget)\b.{0,180}((/releases/download/)|(\.tar\.gz|\.tgz|\.zip|\.exe|\.dmg|\.pkg|\.deb|\.rpm|\.so|\.dll)\b)",
            ]
        ),
    ),
    RegexRule(
        rule_id="python-dynamic-execution",
        title="Python dynamic command execution found.",
        severity="medium",
        category="execution",
        description="Python code can execute shell commands or dynamic code.",
        recommendation="Review before letting an agent run tests, setup, or scripts from this repository.",
        path_globs=["*.py", "**/*.py"],
        patterns=compile_patterns(
            [
                r"\b(os\.system|subprocess\.(run|Popen|call|check_call|check_output)|eval|exec)\s*\(",
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
        path_globs=["*.js", "*.mjs", "*.cjs", "*.ts", "**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"],
        patterns=compile_patterns(
            [
                r"\brequire\(['\"]child_process['\"]\)|\bfrom\s+['\"]child_process['\"]|\b(exec|execSync|spawn|spawnSync)\s*\(",
            ]
        ),
    ),
    RegexRule(
        rule_id="obfuscated-javascript",
        title="Obfuscated JavaScript pattern found.",
        severity="high",
        category="obfuscation",
        description="JavaScript contains patterns commonly used to hide behavior.",
        recommendation="Do not run this code until the obfuscated behavior is decoded and reviewed.",
        path_globs=["*.js", "*.mjs", "*.cjs", "**/*.js", "**/*.mjs", "**/*.cjs"],
        patterns=compile_patterns(
            [
                r"\beval\s*\(\s*atob\s*\(",
                r"\bnew\s+Function\s*\(",
                r"\bString\.fromCharCode\s*\(",
                r"['\"][A-Za-z0-9+/]{180,}={0,2}['\"]",
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
        path_globs=[".github/workflows/*"],
        patterns=compile_patterns([r"^\s*pull_request_target\s*:"]),
    ),
    RegexRule(
        rule_id="github-actions-self-hosted-runner",
        title="Workflow uses a self-hosted runner.",
        severity="medium",
        category="ci",
        description="Self-hosted runners can expose private infrastructure if a workflow is unsafe.",
        recommendation="Verify runner isolation and avoid running untrusted repository code on persistent machines.",
        path_globs=[".github/workflows/*"],
        patterns=compile_patterns([r"runs-on\s*:\s*(\[.*self-hosted.*\]|self-hosted)"]),
    ),
    RegexRule(
        rule_id="crypto-miner-indicator",
        title="Crypto miner indicator found.",
        severity="critical",
        category="malware",
        description="The repository references terms commonly associated with cryptocurrency mining malware.",
        recommendation="Do not run this repository until the miner-related behavior is understood.",
        patterns=compile_patterns([r"\b(xmrig|monero|stratum\+tcp|nanopool|minergate|cryptonight)\b"]),
    ),
    RegexRule(
        rule_id="docker-host-escape-risk",
        title="Container host escape risk pattern found.",
        severity="high",
        category="sandbox",
        description="Docker socket mounts or privileged containers can allow code to control the host.",
        recommendation="Do not run this with host Docker access unless it is fully trusted.",
        patterns=compile_patterns([r"/var/run/docker\.sock|--privileged\b"]),
    ),
]


CUSTOM_RULES: List[CustomRule] = [
    package_json_lifecycle_rule,
    sensitive_network_combo_rule,
    github_actions_secret_remote_rule,
]

