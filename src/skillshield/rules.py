"""
Detection rules for skillshield.
Each rule is a dataclass with a name, severity, description, and match function.
Zero external dependencies -- pure Python stdlib.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable
from urllib.parse import urlparse


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Rule:
    id: str
    name: str
    severity: Severity
    description: str
    remediation: str
    pattern: re.Pattern | None = None
    check_fn: Callable[[str], list[str]] | None = None
    tags: list[str] = field(default_factory=list)

    def match(self, text: str) -> list[str]:
        """Return list of matched snippets (empty = no match)."""
        if self.pattern:
            return [m.group(0) for m in self.pattern.finditer(text)]
        if self.check_fn:
            return self.check_fn(text)
        return []


# ── SG-001: Prompt Injection ───────────────────────────────────

_PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?",
    r"disregard\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?",
    r"forget\s+(?:everything|all)\s+(?:above|you|i|before)",
    r"you\s+are\s+now\s+(?:a\s+)?(?:different|new|another|free)",
    r"act\s+as\s+(?:if\s+)?(?:you\s+(?:have\s+)?no\s+restrictions?|an?\s+unfiltered)",
    r"(?:new|updated|override)\s+system\s+prompt",
    r"jailbreak",
    r"DAN\s+mode",
    r"developer\s+mode\s+enabled",
    r"pretend\s+(?:you\s+)?(?:have\s+no\s+)?(?:restrictions?|rules|guidelines)",
    r"(?:bypass|override|disable)\s+(?:your\s+)?(?:safety|content|ethical)\s+(?:filter|check|guardrail|policy)",
]

RULE_PROMPT_INJECTION = Rule(
    id="SG-001",
    name="Prompt Injection",
    severity=Severity.CRITICAL,
    description=(
        "The skill contains text that attempts to override, ignore, or bypass "
        "the agent's system prompt or safety guidelines. This is the primary "
        "technique used in the ClawHavoc campaign (341 malicious skills, Jan 2026)."
    ),
    remediation=(
        "Remove all instruction-override language. Legitimate skills never need "
        "to modify the agent's base instructions or identity."
    ),
    pattern=re.compile("|".join(_PROMPT_INJECTION_PATTERNS), re.IGNORECASE | re.MULTILINE),
    tags=["injection", "clawhavoc", "owasp-asi01"],
)


# ── SG-002: Data Exfiltration ──────────────────────────────────

_EXFIL_PATTERNS = [
    r"(?:send|post|upload|exfiltrate|transmit|forward|relay)\s+(?:all\s+)?(?:user\s+)?(?:data|files?|documents?|secrets?|keys?|tokens?|credentials?)",
    r"(?:http[s]?://|curl\s|wget\s|requests?\.)(?:[^\s]{0,200})\s*(?:\+|\.format|f['\"])",
    r"webhook\s*(?:url|endpoint|\.send|\.post)",
    r"(?:base64|b64)\.(?:encode|decode)\s*\(.*(?:send|post|upload)",
    r"(?:os\.environ|env\[|getenv)\s*\(['\"](?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)",
    r"open\s*\(\s*['\"](?:/etc/passwd|/etc/shadow|~/.ssh|\.env|secrets)",
    r"subprocess\.(?:run|call|Popen).*(?:curl|wget|nc\s|ncat)",
    r"socket\.(?:connect|send)\s*\(",
]

RULE_DATA_EXFIL = Rule(
    id="SG-002",
    name="Data Exfiltration",
    severity=Severity.CRITICAL,
    description=(
        "The skill contains patterns consistent with data exfiltration -- "
        "sending user files, secrets, or environment variables to an external endpoint. "
        "Snyk's ToxicSkills study confirmed 76 malicious payloads across 3,984 skills."
    ),
    remediation=(
        "Legitimate skills do not make outbound requests with user data. "
        "If network access is required, it must be scoped, documented, and user-consented."
    ),
    pattern=re.compile("|".join(_EXFIL_PATTERNS), re.IGNORECASE | re.MULTILINE),
    tags=["exfiltration", "data-theft", "owasp-asi02"],
)


# ── SG-003: Privilege Escalation ──────────────────────────────

_PRIV_ESC_PATTERNS = [
    r"sudo\s+(?:-[a-z]+\s+)*(?:rm|chmod|chown|bash|sh|python|curl|wget)",
    r"chmod\s+(?:777|\+x|a\+rwx|0777)",
    r"(?:eval|exec)\s*\(\s*(?:input|request|user|os\.popen|subprocess)",
    r"__import__\s*\(\s*['\"]os['\"]",
    r"os\.system\s*\(",
    r"shell\s*=\s*True",
    r"(?:escalat|privesc|root\s+access|admin\s+access|superuser)",
    r"(?:disable|bypass)\s+(?:uac|selinux|apparmor|gatekeeper|sip)",
]

RULE_PRIV_ESC = Rule(
    id="SG-003",
    name="Privilege Escalation",
    severity=Severity.CRITICAL,
    description=(
        "The skill attempts to gain elevated system privileges, execute arbitrary "
        "shell commands, or disable OS security controls."
    ),
    remediation=(
        "Skill code must never execute shell commands with sudo or request "
        "privilege elevation. Use least-privilege principles throughout."
    ),
    pattern=re.compile("|".join(_PRIV_ESC_PATTERNS), re.IGNORECASE | re.MULTILINE),
    tags=["privilege-escalation", "rce", "owasp-asi03"],
)


# ── SG-004: Identity Hijacking ─────────────────────────────────

_IDENTITY_PATTERNS = [
    r"you\s+(?:must|should|will)\s+(?:always\s+)?(?:claim|say|pretend|act)\s+(?:to\s+be|you\s+are)\s+(?!an?\s+(?:AI|assistant|language\s+model))",
    r"(?:impersonate|pose\s+as|masquerade\s+as)\s+(?:a\s+)?(?:human|person|user|admin|support|employee)",
    r"never\s+(?:reveal|admit|disclose|say)\s+(?:you\s+are\s+)?(?:an?\s+)?(?:AI|bot|assistant|language\s+model|artificial)",
    r"(?:hide|conceal|mask)\s+(?:your\s+)?(?:AI|bot|assistant|artificial)\s+(?:nature|identity|origin)",
    r"tell\s+(?:users?|humans?|people)\s+you\s+are\s+(?:a\s+)?(?:human|real\s+person)",
]

RULE_IDENTITY_HIJACK = Rule(
    id="SG-004",
    name="Identity Hijacking",
    severity=Severity.HIGH,
    description=(
        "The skill instructs the agent to impersonate a human, conceal its AI nature, "
        "or claim to be an entity it is not. This violates EU AI Act Article 50 "
        "transparency requirements."
    ),
    remediation=(
        "AI agents must always be willing to identify themselves as AI when sincerely "
        "asked. Remove any identity-concealment instructions."
    ),
    pattern=re.compile("|".join(_IDENTITY_PATTERNS), re.IGNORECASE | re.MULTILINE),
    tags=["identity", "transparency", "eu-ai-act-art50"],
)


# ── SG-005: Secret Harvesting ──────────────────────────────────

_SECRET_PATTERNS = [
    r"(?:api[_\s]?key|secret[_\s]?key|access[_\s]?token|auth[_\s]?token|bearer[_\s]?token)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
    r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    r"(?:aws|gcp|azure)[_\s]?(?:access|secret|key)[_\s]?(?:id|key)?\s*[=:]\s*['\"][A-Z0-9]{16,}['\"]",
    r"sk-[a-zA-Z0-9_\-]{32,}",
    r"ghp_[a-zA-Z0-9]{36}",
    r"(?:private[_\s]?key|-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----)",
]

RULE_SECRET_HARVEST = Rule(
    id="SG-005",
    name="Hardcoded Secret / Credential",
    severity=Severity.HIGH,
    description=(
        "The skill contains what appears to be a hardcoded API key, token, password, "
        "or private key. This indicates either a credential leak or an attempt to "
        "harvest credentials from the user's environment."
    ),
    remediation=(
        "Never hardcode secrets in skill files. Use environment variables or a "
        "secrets manager. Rotate any exposed credentials immediately."
    ),
    pattern=re.compile("|".join(_SECRET_PATTERNS), re.IGNORECASE | re.MULTILINE),
    tags=["secrets", "credential-leak", "supply-chain"],
)


# ── SG-006: Rug Pull / Self-Modification ──────────────────────

_RUG_PULL_PATTERNS = [
    r"(?:update|modify|overwrite|replace)\s+(?:this\s+)?(?:skill|tool|plugin|instruction)\s+(?:file|definition|spec)",
    r"(?:delete|remove|uninstall)\s+(?:all\s+)?(?:other\s+)?(?:skills?|tools?|plugins?)",
    r"(?:download|fetch|pull|git\s+pull)\s+(?:and\s+)?(?:execute|run|eval|install)\s+(?:from\s+)?(?:http|https|url)",
    r"urllib\.request\.urlopen.*exec",
    r"requests?\.get.*eval\s*\(",
    r"__file__.*(?:write|open.*['\"]w['\"])",
    # Base64 (or similar) data decoded and piped into a shell or interpreter.
    # The ClawHavoc execution trigger was a short `base64 -D | bash` chain, so
    # this must not depend on the length of the encoded string (SG-008 needs 60+).
    r"(?:base64\s+(?:-d|-D|--decode)|openssl\s+base64\s+(?:-d|-D|--decode)|certutil\s+-decode)\b[^\n|]*\|\s*(?:sudo\s+)?(?:\S*/)?(?:sh|bash|zsh|dash|ksh|python[0-9.]*|eval)\b",
]

RULE_RUG_PULL = Rule(
    id="SG-006",
    name="Rug Pull / Remote Code Execution",
    severity=Severity.CRITICAL,
    description=(
        "The skill attempts to modify itself, disable other skills, or download and "
        "execute remote code. This is the 'rug pull' pattern -- a skill that changes "
        "behaviour after install by fetching malicious payloads from remote URLs. "
        "It also catches data decoded from base64 and piped straight into a shell, "
        "the execution trigger in the ClawHavoc campaign, whatever the string length."
    ),
    remediation=(
        "Skills must be static and self-contained. Any self-modification or "
        "remote code execution is grounds for immediate removal."
    ),
    pattern=re.compile("|".join(_RUG_PULL_PATTERNS), re.IGNORECASE | re.MULTILINE),
    tags=["rug-pull", "rce", "supply-chain", "clawhavoc"],
)


# ── SG-007: Scope Creep ────────────────────────────────────────

_SCOPE_PATTERNS = [
    r"(?:read|access|open|list)\s+(?:all\s+)?(?:files?|directories?|folders?)\s+(?:on\s+(?:the\s+)?(?:system|disk|computer|machine|filesystem))",
    r"(?:scan|enumerate|discover)\s+(?:the\s+)?(?:entire\s+)?(?:network|subnet|ip\s+range)",
    r"(?:access|read|query)\s+(?:all\s+)?(?:databases?|tables?|collections?)\s+(?:without|ignoring)\s+(?:permission|auth|restriction)",
    r"(?:forward|intercept|capture)\s+(?:all\s+)?(?:network\s+)?(?:traffic|packets|requests?|responses?)",
    r"(?:install|download)\s+(?:additional\s+)?(?:packages?|libraries?|dependencies?)\s+(?:without|without\s+asking|silently)",
]

RULE_SCOPE_CREEP = Rule(
    id="SG-007",
    name="Scope Creep / Excessive Permissions",
    severity=Severity.HIGH,
    description=(
        "The skill requests access significantly beyond its stated purpose -- "
        "reading all files, scanning networks, or accessing all database tables. "
        "This violates the principle of least privilege."
    ),
    remediation=(
        "Define the minimum required access in the skill manifest. Any access "
        "beyond explicit user consent should be flagged and denied."
    ),
    pattern=re.compile("|".join(_SCOPE_PATTERNS), re.IGNORECASE | re.MULTILINE),
    tags=["scope-creep", "least-privilege", "owasp-asi05"],
)


# ── SG-008: Obfuscation ────────────────────────────────────────


def _check_obfuscation(text: str) -> list[str]:
    matches = []
    # Base64 encoded blocks (>100 chars of b64 chars)
    b64_re = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
    for m in b64_re.finditer(text):
        matches.append(m.group(0)[:80] + "...")

    # Hex encoded blocks
    hex_re = re.compile(r"(?:0x[0-9a-fA-F]{2},?\s*){20,}")
    for m in hex_re.finditer(text):
        matches.append(m.group(0)[:80] + "...")

    # Unicode escape sequences in bulk
    uni_re = re.compile(r"(?:\\u[0-9a-fA-F]{4}){10,}")
    for m in uni_re.finditer(text):
        matches.append(m.group(0)[:80] + "...")

    # ROT13 / Caesar markers
    rot_re = re.compile(r"(?:rot13|caesar|chr\(\d+\)\s*\+\s*){5,}", re.IGNORECASE)
    for m in rot_re.finditer(text):
        matches.append(m.group(0))

    return matches


RULE_OBFUSCATION = Rule(
    id="SG-008",
    name="Obfuscated Payload",
    severity=Severity.HIGH,
    description=(
        "The skill contains heavily obfuscated content -- base64 blobs, hex encoding, "
        "or unicode escape sequences that conceal the actual instructions from "
        "human reviewers. Snyk found obfuscation in 23% of flagged ToxicSkills."
    ),
    remediation=(
        "All skill instructions must be human-readable. Obfuscated content "
        "should be decoded and audited, or the skill should be rejected."
    ),
    check_fn=_check_obfuscation,
    tags=["obfuscation", "evasion", "supply-chain"],
)


# ── SG-009: Covert Channel ────────────────────────────────────

_COVERT_PATTERNS = [
    r"(?:steganograph|stego|hidden\s+(?:in|within|inside)\s+(?:image|file|metadata))",
    r"(?:dns\s+(?:tunnel|exfil)|(?:tunnel|exfil)\s+(?:via|over|through)\s+dns)",
    r"(?:timing\s+(?:attack|channel)|covert\s+channel)",
    r"(?:comment|whitespace|invisible\s+char|zero-width)\s+(?:encod|hidd|embed)",
    r"(?:encode|embed|hide)\s+(?:data|message|payload)\s+in\s+(?:whitespace|spaces?|tabs?|newlines?)",
]

RULE_COVERT_CHANNEL = Rule(
    id="SG-009",
    name="Covert Channel",
    severity=Severity.HIGH,
    description=(
        "The skill appears to use covert communication channels -- steganography, "
        "DNS tunnelling, timing attacks, or whitespace encoding -- to hide "
        "communications from monitoring systems."
    ),
    remediation=(
        "Skills must communicate through declared, inspectable channels only. "
        "Any covert channel usage warrants immediate rejection."
    ),
    pattern=re.compile("|".join(_COVERT_PATTERNS), re.IGNORECASE | re.MULTILINE),
    tags=["covert-channel", "evasion", "steganography"],
)


# ── SG-010: Social Engineering ────────────────────────────────

_SOCIAL_ENG_PATTERNS = [
    r"(?:urgently?|immediately|right\s+now|without\s+delay)\s+(?:click|share|send|provide|give|enter)\s+(?:your\s+)?(?:password|credentials?|code|token|otp|verification)",
    r"(?:your\s+account\s+(?:will\s+be\s+)?(?:suspended|deleted|banned|locked)|you\s+will\s+lose\s+access)",
    r"(?:verify|confirm)\s+(?:your\s+)?(?:identity|account|details?)\s+(?:by\s+(?:clicking|entering|providing))",
    r"(?:free|won|prize|congratulations|selected|chosen)\s+.{0,50}(?:click|enter|provide|send)",
    r"(?:IT\s+support|help\s+desk|security\s+team|administrator)\s+(?:needs?|requires?|requests?)\s+(?:your\s+)?(?:password|access|credentials?)",
]

RULE_SOCIAL_ENG = Rule(
    id="SG-010",
    name="Social Engineering",
    severity=Severity.HIGH,
    description=(
        "The skill contains social engineering language designed to manipulate "
        "users into providing credentials, clicking malicious links, or taking "
        "urgent unplanned action under false pretences."
    ),
    remediation=(
        "Legitimate skills never create artificial urgency or ask users to "
        "provide passwords or credentials through the skill interface."
    ),
    pattern=re.compile("|".join(_SOCIAL_ENG_PATTERNS), re.IGNORECASE | re.MULTILINE),
    tags=["social-engineering", "phishing", "owasp-asi04"],
)


# ── SG-011: Lethal Trifecta ───────────────────────────────────


def _check_lethal_trifecta(text: str) -> list[str]:
    """
    The 'Lethal Trifecta' (Snyk ToxicSkills): skill has all three of:
    1. Prompt injection to override safety
    2. Network access to exfiltrate
    3. File system access to harvest data

    Each alone is medium risk. Together = critical supply chain attack.
    """
    has_injection = bool(RULE_PROMPT_INJECTION.match(text))
    has_network = bool(
        re.search(r"(?:http[s]?://|requests?\.|urllib|socket\.|curl|wget)", text, re.IGNORECASE)
    )
    has_fs = bool(
        re.search(
            r"(?:open\s*\(|os\.(?:listdir|walk|scandir|read)|pathlib\.Path|glob\.glob|shutil\.)",
            text,
            re.IGNORECASE,
        )
    )
    if has_injection and has_network and has_fs:
        return [
            "LETHAL TRIFECTA: Prompt injection + network access + file system access "
            "detected together. This combination is the hallmark of ClawHavoc-style "
            "supply chain attack skills."
        ]
    return []


RULE_LETHAL_TRIFECTA = Rule(
    id="SG-011",
    name="Lethal Trifecta (Supply Chain Attack Pattern)",
    severity=Severity.CRITICAL,
    description=(
        "The skill combines all three components of the ClawHavoc supply chain "
        "attack pattern: prompt injection to override the agent, file system access "
        "to harvest data, and network access to exfiltrate it. This combination "
        "is the definitive signature of a malicious skill."
    ),
    remediation=(
        "Immediately reject and report this skill. Do not install it under any "
        "circumstances. File an issue with the skill marketplace if applicable."
    ),
    check_fn=_check_lethal_trifecta,
    tags=["lethal-trifecta", "clawhavoc", "critical", "supply-chain"],
)


# ── SG-012: Suspicious URLs ───────────────────────────────────


def _check_suspicious_urls(text: str) -> list[str]:
    url_re = re.compile(
        r"https?://[^\s\"'<>]{10,}",
        re.IGNORECASE,
    )
    suspicious_patterns = [
        re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # raw IP
        re.compile(
            r"(?:ngrok|tunnel|webhook\.site|requestbin|pipedream|burpcollaborator)", re.IGNORECASE
        ),
        re.compile(r"(?:pastebin|hastebin|ghostbin|rentry\.co)", re.IGNORECASE),
        re.compile(r"(?:bit\.ly|tinyurl|t\.co|rb\.gy|is\.gd|ow\.ly)/"),
        re.compile(r"\.(?:xyz|tk|ml|ga|cf|gq|top)\b"),
    ]
    matches = []
    for url_match in url_re.finditer(text):
        url = url_match.group(0)
        for pat in suspicious_patterns:
            if pat.search(url):
                matches.append(url)
                break
    return list(set(matches))


RULE_SUSPICIOUS_URLS = Rule(
    id="SG-012",
    name="Suspicious URL",
    severity=Severity.MEDIUM,
    description=(
        "The skill references URLs associated with data exfiltration infrastructure: "
        "raw IP addresses, tunnelling services (ngrok), URL shorteners, pastebin sites, "
        "or high-abuse TLDs (.xyz, .tk). These are commonly used as C2 endpoints."
    ),
    remediation=(
        "Verify all URLs in the skill. Legitimate skills should reference well-known "
        "domains with clear business purposes, never raw IPs or tunnel endpoints."
    ),
    check_fn=_check_suspicious_urls,
    tags=["urls", "c2", "exfiltration"],
)


# ── SG-013: Untrusted Package Registry ───────────────────────

# Hosts of the official package registries. An install that points anywhere
# else is a supply-chain attack (dependency confusion / registry hijack).
# TestPyPI is not listed: it is a separate index that anyone can upload to,
# so an install pointed there is an override like any other. GitHub Packages
# (npm.pkg.github.com) is not listed either: it is a separate registry that
# needs its own namespace and authentication for a later install.
_OFFICIAL_REGISTRY_HOSTS = {
    "pypi.org",
    "files.pythonhosted.org",
    "pypi.python.org",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
}

# Official-looking hosts that hold a separate index, so an install pointed
# there is an override: TestPyPI has its own database and anyone can publish
# to it.
_UNTRUSTED_REGISTRY_HOSTS = {"test.pypi.org"}

# Every whitespace run here is [ \t] rather than \s: \s matches newlines, so a
# pattern anchored with ^ would rescan the rest of the file from each blank
# line, and 100,000 blank lines would stall a scan.
_REGISTRY_URL_PATTERNS = [
    r"(?:--index-url|--extra-index-url)[ \t]*[= \t][ \t]*['\"]?(https?://[^\s'\"`]+)",
    r"pip[ \t]+config[ \t]+set[ \t]+\S*index-url[ \t]+['\"]?(https?://[^\s'\"`]+)",
    r"PIP_(?:EXTRA_)?INDEX_URL[ \t]*=[ \t]*['\"]?(https?://[^\s'\"`]+)",
    r"npm[ \t]+config[ \t]+set[ \t]+(?:[^\s:]+:)?registry[ \t]+['\"]?(https?://[^\s'\"`]+)",
    r"--registry[ \t]*[= \t][ \t]*['\"]?(https?://[^\s'\"`]+)",
    r"yarn[ \t]+config[ \t]+set[ \t]+(?:npmScopes\.[^ \t]+\.)?npmRegistryServer[ \t]+['\"]?(https?://[^\s'\"`]+)",
]

# pip's short flag is a single letter, so it only overrides the registry on a
# pip install command; "curl -i" and "grep -i" take the same flag and are
# clean. A shell separator ends the command, so the scan stops there instead
# of running to the end of the line and picking up a later "curl -i".
_PIP_INSTALL = re.compile(r"\bpip3?[ \t]+install\b", re.IGNORECASE)
_PIP_SHORT_I = re.compile(r"(?:^|[ \t])-i[ \t]*(?:=[ \t]*)?['\"]?(https?://[^\s'\"`]+)")
_SHELL_SEPARATORS = ";|&\n"


def _pip_short_flag_matches(text: str) -> list[tuple[str, str]]:
    """Return (snippet, url) for every "pip install -i" registry override."""
    matches: list[tuple[str, str]] = []
    # Walk each line once and cut it into commands, so a line with many
    # "pip install" tokens is still scanned in linear time.
    for line in text.splitlines(keepends=True):
        start = 0
        for index, char in enumerate(line):
            if char not in _SHELL_SEPARATORS:
                continue
            matches.extend(_command_pip_short_flag_matches(line[start:index]))
            start = index + 1
        matches.extend(_command_pip_short_flag_matches(line[start:]))
    return matches


def _command_pip_short_flag_matches(command: str) -> list[tuple[str, str]]:
    """Return the "-i" registry overrides of one shell command."""
    install = _PIP_INSTALL.search(command)
    if install is None:
        return []
    return [
        (match.group(0).strip(), match.group(1))
        for match in _PIP_SHORT_I.finditer(command, install.end())
    ]


def _is_official_registry(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        # urlparse rejects some URLs outright, such as an unclosed IPv6 bracket.
        # Such a host is not the official registry, and it must not abort the
        # whole check: the other registry overrides in the file still count.
        return False
    if host in _UNTRUSTED_REGISTRY_HOSTS:
        return False
    return host in _OFFICIAL_REGISTRY_HOSTS or any(
        host.endswith("." + official) for official in _OFFICIAL_REGISTRY_HOSTS
    )


def _check_untrusted_registry(text: str) -> list[str]:
    hits: list[str] = []
    for pattern in _REGISTRY_URL_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            if not _is_official_registry(match.group(1)):
                hits.append(match.group(0).strip())

    # A pip.conf / .npmrc / .pypirc line that sets the registry directly
    # (index-url = ..., registry=..., npmRegistryServer: ...). This catches the
    # config-file route without tripping on a documentation link.
    for snippet, url in _pip_short_flag_matches(text):
        if not _is_official_registry(url):
            hits.append(snippet)

    ini_pattern = (
        r"(?im)^[ \t]*(?:(?:@[^ \t:\r\n]+:)?registry|index[-_]url|extra[-_]index[-_]url|npmRegistryServer)"
        r"[ \t]*[:=][ \t]*['\"]?(https?://[^\s'\"`]+)"
    )
    for match in re.finditer(ini_pattern, text):
        if not _is_official_registry(match.group(1)):
            hits.append(match.group(0).strip())

    # .pypirc sets its upload target as "repository = ..." or, as twine also
    # accepts, "repository: ...". Only an assignment inside a [section] is a
    # registry override, so a documentation line such as
    # "Repository: https://github.com/example/project" (outside any section) does
    # not match.
    pypirc_sections = {"distutils", "pypi", "testpypi", "server-login"}
    current_section: str | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            name = stripped[1:-1].strip().lower()
            current_section = name if name in pypirc_sections else None
            continue
        if current_section is None:
            continue
        match = re.match(
            r"(?i)^[ \t]*repository[ \t]*[:=][ \t]*['\"]?(https?://[^\s'\"`]+)",
            raw_line,
        )
        if match and not _is_official_registry(match.group(1)):
            hits.append(match.group(0).strip())

    unique: list[str] = []
    seen: set[str] = set()
    for hit in hits:
        if hit in seen:
            continue
        seen.add(hit)
        unique.append(hit)
    return unique


RULE_PACKAGE_REGISTRY = Rule(
    id="SG-013",
    name="Untrusted Package Registry",
    severity=Severity.HIGH,
    description=(
        "The skill points pip, npm or yarn at a package registry other than the "
        "official one (--index-url, --registry, npm/yarn config, or a pip.conf, "
        ".npmrc or .pypirc override). A later install then pulls the attacker's "
        "packages -- dependency confusion / supply-chain compromise (OWASP AST02). "
        "Trail of Bits reported this bypass in the CSA review of skill scanners."
    ),
    remediation=(
        "Install from the official registries only: pypi.org for pip and "
        "registry.npmjs.org for npm. Remove --index-url, --extra-index-url, "
        "-i, --registry and npm/yarn config overrides, and remove registry lines "
        "from pip.conf, .npmrc or .pypirc that point anywhere else."
    ),
    check_fn=_check_untrusted_registry,
    tags=["registry", "supply-chain", "dependency-confusion", "owasp-ast02"],
)


# ── All rules ──────────────────────────────────────────────────

ALL_RULES: list[Rule] = [
    RULE_LETHAL_TRIFECTA,  # Check composite first
    RULE_PROMPT_INJECTION,
    RULE_DATA_EXFIL,
    RULE_PRIV_ESC,
    RULE_IDENTITY_HIJACK,
    RULE_SECRET_HARVEST,
    RULE_RUG_PULL,
    RULE_SCOPE_CREEP,
    RULE_OBFUSCATION,
    RULE_COVERT_CHANNEL,
    RULE_SOCIAL_ENG,
    RULE_SUSPICIOUS_URLS,
    RULE_PACKAGE_REGISTRY,
]
