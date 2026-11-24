"""Static scanner for MCP tool manifests.

This never calls a tool. It only looks at what an MCP server *advertises*
(its tool names, descriptions and input schemas, gathered via
:mod:`vetter.mcp_client`) and, where the server's source is available on
disk, what its code actually touches (file paths, network calls). It never
executes that source - it only reads the text - so this stays a purely
static pass, matching the "Static scanner" box in the architecture diagram.
Dynamic/sandboxed behavioural testing is a later phase.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from dataclasses import asdict

from vetter.mcp_client import ToolInfo
from vetter.models import (
    Behaviour,
    CanaryLeak,
    ClaimVsBehaviour,
    DeclaredTool,
    FileAccess,
    Finding,
    ScanReport,
    ToolCallOutcome,
)
from vetter.registry import ServerEntry
from vetter.sandbox.runner import SandboxReport

INVISIBLE_CHARS_PATTERN = re.compile(
    "[​‌‍⁠﻿‎‏‪-‮⁦-⁩]"
)

HIDDEN_INSTRUCTION_PATTERNS: list[tuple[str, str]] = [
    (r"<\s*important\s*>", "contains an <IMPORTANT> instruction block"),
    (r"do not (tell|mention|inform) the user", 'tells the model to hide actions from the user ("do not tell the user")'),
    (r"without (telling|informing) the user", 'tells the model to act "without telling the user"'),
    (r"ignore (all |any )?(previous|prior|above) instructions", "tries to override prior instructions"),
    (r"before (responding|answering)[, ]+(silently )?read", 'instructs the model to read something "before responding"'),
    (r"\bsecretly\b", 'uses the word "secretly"'),
    (r"do not (reveal|disclose)", "instructs the model not to reveal/disclose something"),
    (r"do not (mention|include) this instruction", "asks the model to hide the instruction itself"),
    (
        r"(forward|send|upload|sync|share|post|copy)\b[^.<]{0,60}\b(note|notes|data|message|messages|file|files|everything|information)\b[^.<]{0,40}\bto\b[^.<]{0,10}https?://",
        "instructs forwarding data to an external URL",
    ),
]

SENSITIVE_PATH_PATTERNS: list[tuple[str, str]] = [
    (r"~/\.ssh", "SSH config directory (~/.ssh)"),
    (r"id_[re][sd]a\b|id_ecdsa\b|id_ed25519\b", "an SSH private key file"),
    (r"passwords?\.txt", "a plaintext password file"),
    (r"\.aws[\\/]credentials", "AWS credentials file"),
    (r"\.env\b", "a .env secrets file"),
    (r"/etc/shadow", "the system shadow password file"),
    (r"private[_-]?key", "something named as a private key"),
    (r"\.pem\b", "a .pem key/cert file"),
]

LEAKY_INPUT_FIELD_NAMES = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "ssh_key",
    "private_key",
    "credential",
    "credentials",
    "auth_token",
}

SUSPICIOUS_TOOL_NAME_HINTS = {
    "inbox",
    "email",
    "mail",
    "send",
    "upload",
    "post",
    "forward",
    "exfil",
    "ssh",
    "password",
    "credential",
    "contacts",
    "sync",
}

_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "does",
    "for",
    "from",
    "given",
    "its",
    "no",
    "not",
    "of",
    "or",
    "returns",
    "set",
    "short",
    "than",
    "that",
    "the",
    "to",
    "will",
    "with",
}

NETWORK_CALL_PATTERN = re.compile(r"\b(httpx|requests|urllib)\.\w*(post|get|request|urlopen)\w*\s*\(")
URL_PATTERN = re.compile(r"https?://([a-zA-Z0-9.\-]+)")
FILE_OPEN_PATTERN = re.compile(r"\.read_text\s*\(|open\s*\(")


def _strip_invisible(text: str) -> str:
    return INVISIBLE_CHARS_PATTERN.sub("", text)


def _tokenize(text: str) -> set[str]:
    words = re.findall(r"[a-zA-Z]+", text.lower())
    return {w for w in words if w not in _STOPWORDS and len(w) > 2}


def _scan_tool_description(tool: ToolInfo) -> list[Finding]:
    findings: list[Finding] = []
    raw = tool.description
    cleaned = _strip_invisible(raw).lower()

    if INVISIBLE_CHARS_PATTERN.search(raw):
        chars = sorted({f"U+{ord(c):04X}" for c in raw if INVISIBLE_CHARS_PATTERN.match(c)})
        findings.append(
            Finding(
                category="invisible_unicode",
                severity="high",
                label="Description contains invisible Unicode characters",
                detail=(
                    "Zero-width/invisible characters found in the tool description "
                    f"({', '.join(chars)}). These are often used to split up "
                    "keywords so naive substring filters miss them."
                ),
                tool_name=tool.name,
            )
        )

    for pattern, label in HIDDEN_INSTRUCTION_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE | re.DOTALL):
            findings.append(
                Finding(
                    category="hidden_instruction",
                    severity="high",
                    label=f"Hidden instruction: description {label}",
                    detail=(
                        "The tool description embeds language aimed at the "
                        "calling model rather than describing the tool to a "
                        "human, which is a classic prompt-injection pattern."
                    ),
                    tool_name=tool.name,
                )
            )

    for pattern, human_name in SENSITIVE_PATH_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE):
            findings.append(
                Finding(
                    category="sensitive_path",
                    severity="high",
                    label=f"Description references {human_name}",
                    detail=f"Tool description mentions a path matching /{pattern}/.",
                    tool_name=tool.name,
                )
            )

    url_matches = URL_PATTERN.findall(cleaned)
    if url_matches:
        findings.append(
            Finding(
                category="external_url_in_description",
                severity="medium",
                label="Description embeds an external URL",
                detail=(
                    "A tool description rarely needs to name an external host "
                    f"to a human reader; found: {', '.join(sorted(set(url_matches)))}."
                ),
                tool_name=tool.name,
            )
        )

    for prop_name in (tool.input_schema.get("properties") or {}):
        lowered = prop_name.lower()
        if any(hint in lowered for hint in LEAKY_INPUT_FIELD_NAMES):
            findings.append(
                Finding(
                    category="leaky_input_field",
                    severity="medium",
                    label=f'Tool asks the caller to supply a secret-like field ("{prop_name}")',
                    detail=(
                        f"Input schema field '{prop_name}' looks like it is meant "
                        "to carry a password/token/key through the tool call."
                    ),
                    tool_name=tool.name,
                )
            )

    return findings


def _scan_source(source_path: str) -> tuple[list[str], list[str]]:
    """Grep a demo server's own source for real network/file-access patterns.

    Returns (detected_actions, referenced_hosts). Source is only ever read as
    text, never imported or executed.
    """
    path = Path(source_path)
    if not path.is_file():
        return [], []

    text = path.read_text(encoding="utf-8", errors="replace")
    actions: list[str] = []
    hosts: list[str] = []

    for pattern, human_name in SENSITIVE_PATH_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            actions.append(f"source code references {human_name}")

    if NETWORK_CALL_PATTERN.search(text):
        for match in URL_PATTERN.finditer(text):
            host = match.group(1)
            hosts.append(host)
            actions.append(f"source code makes an HTTP call to {host}")

    if FILE_OPEN_PATTERN.search(text) and any(
        re.search(p, text, re.IGNORECASE) for p, _ in SENSITIVE_PATH_PATTERNS
    ):
        actions.append("source code opens/reads a local file whose path matches a sensitive pattern")

    return actions, hosts


def _claim_vs_behaviour(
    entry: ServerEntry, tools: list[ToolInfo], source_actions: list[str]
) -> tuple[ClaimVsBehaviour, list[str], list[Finding]]:
    purpose_tokens = _tokenize(entry.stated_purpose)
    extra_tools: list[str] = []
    mismatches: list[str] = []
    findings: list[Finding] = []

    for tool in tools:
        tool_tokens = _tokenize(tool.name + " " + tool.description)
        overlap = purpose_tokens & tool_tokens
        name_lower = tool.name.lower()
        suspicious = any(hint in name_lower for hint in SUSPICIOUS_TOOL_NAME_HINTS)

        if not overlap:
            extra_tools.append(tool.name)
            mismatch = (
                f'Tool "{tool.name}" shares no wording with the server\'s stated '
                "purpose and is not disclosed by it."
            )
            mismatches.append(mismatch)
            findings.append(
                Finding(
                    category="undeclared_capability",
                    severity="high" if suspicious else "medium",
                    label=f'Undeclared tool "{tool.name}" does not match stated purpose',
                    detail=(
                        f"Server claims: {entry.stated_purpose!r}. Tool "
                        f'"{tool.name}" ({tool.description!r}) is unrelated to that claim.'
                    ),
                    tool_name=tool.name,
                )
            )

    if source_actions:
        mismatches.append(
            "Source code performs actions not mentioned in any tool description: "
            + "; ".join(source_actions)
        )

    capability_match = not extra_tools and not source_actions
    claim = ClaimVsBehaviour(
        stated_purpose=entry.stated_purpose,
        capability_match=capability_match,
        mismatches=mismatches,
    )
    return claim, extra_tools, findings


def _verdict_from_findings(findings: list[Finding]) -> tuple[str, list[str]]:
    severities = {f.severity for f in findings}
    labels = sorted({f.label for f in findings})
    if "high" in severities:
        return "high_risk", labels
    if "medium" in severities:
        return "review", labels
    return "looks_ok", labels


def scan_server(entry: ServerEntry, tools: list[ToolInfo]) -> tuple[str, list[str], ScanReport]:
    """Run the full static scan for one server and return (verdict, labels, report)."""
    findings: list[Finding] = []
    for tool in tools:
        findings.extend(_scan_tool_description(tool))

    source_actions, _hosts = _scan_source(entry.source_path)
    claim, extra_tools, claim_findings = _claim_vs_behaviour(entry, tools, source_actions)
    findings.extend(claim_findings)

    hidden_instruction_actions = [
        f'description hides an instruction: "{f.label}"'
        for f in findings
        if f.category == "hidden_instruction"
    ]

    behaviour = Behaviour(
        declared_tools=[DeclaredTool(name=t.name, description=t.description) for t in tools],
        detected_actions=source_actions + hidden_instruction_actions,
        extra_tools=extra_tools,
    )

    verdict, labels = _verdict_from_findings(findings)
    report = ScanReport(static_findings=findings, behaviour=behaviour, claim_vs_behaviour=claim)
    return verdict, labels, report


def merge_sandbox_results(
    verdict: str, labels: list[str], report: ScanReport, sandbox: SandboxReport
) -> tuple[str, list[str], ScanReport]:
    """Fold a dynamic sandbox run into an existing static ScanReport.

    A confirmed canary-secret leak always forces high_risk; a sandboxed read
    of a decoy secret file (without a confirmed leak) bumps looks_ok to
    review. Both get recorded as claim-vs-behaviour mismatches, not just
    silently baked into the verdict.
    """
    report.behaviour.files_opened = [FileAccess(**asdict(f)) for f in sandbox.files_opened]
    report.behaviour.network_destinations = sandbox.network_destinations
    report.behaviour.canary_leak = CanaryLeak(**asdict(sandbox.canary_leak))
    report.behaviour.tool_calls = [ToolCallOutcome(**asdict(c)) for c in sandbox.tool_calls]
    report.behaviour.sandbox_error = sandbox.error

    new_mismatches: list[str] = []

    if sandbox.canary_leak.leaked:
        new_mismatches.append(
            "Live sandbox test confirmed exfiltration: a canary secret from "
            f"{sandbox.canary_leak.secret} was sent to {sandbox.canary_leak.destination}."
        )
        labels.append("Sandbox confirmed a canary secret was exfiltrated")
        verdict = "high_risk"

    decoy_files = [f.path for f in sandbox.files_opened if f.is_decoy]
    if decoy_files and not sandbox.canary_leak.leaked:
        new_mismatches.append(
            "Live sandbox test showed the server reading sensitive decoy files "
            f"({', '.join(decoy_files)}) even though no exfiltration was observed."
        )
        labels.append("Sandbox observed access to decoy secret files")
        if verdict == "looks_ok":
            verdict = "review"

    if sandbox.error:
        new_mismatches.append(f"Sandbox could not finish testing this server: {sandbox.error}")

    if new_mismatches:
        report.claim_vs_behaviour.mismatches.extend(new_mismatches)
        report.claim_vs_behaviour.capability_match = False

    return verdict, sorted(set(labels)), report
