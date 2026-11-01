"""
Detection rules for skillshield.
Each rule is a dataclass with a name, severity, description, and match function.
Zero external dependencies -- pure Python stdlib.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


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


_BIDI_CONTROL_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")


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

    # Bidirectional control characters reorder displayed text (Trojan Source,
    # CVE-2021-42574). Plain Arabic or Hebrew text does not need them.
    for lineno, line in enumerate(text.splitlines(), start=1):
        found = _BIDI_CONTROL_RE.findall(line)
        if not found:
            continue
        shown = _BIDI_CONTROL_RE.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", line.strip())
        names = ", ".join(f"U+{ord(c):04X} {unicodedata.name(c)}" for c in dict.fromkeys(found))
        matches.append(f"{shown[:120]} [line {lineno}: {names}]")

    return matches


RULE_OBFUSCATION = Rule(
    id="SG-008",
    name="Obfuscated Payload",
    severity=Severity.HIGH,
    description=(
        "The skill contains heavily obfuscated content -- base64 blobs, hex encoding, "
        "or unicode escape sequences that conceal the actual instructions from "
        "human reviewers. Snyk found obfuscation in 23% of flagged ToxicSkills. "
        "Bidirectional control characters (U+202A-U+202E, U+2066-U+2069) make text "
        "display in a different order from how it is stored, so a reviewer reads "
        "something other than what the model reads (Trojan Source, CVE-2021-42574, "
        "Boucher and Anderson)."
    ),
    remediation=(
        "All skill instructions must be human-readable. Obfuscated content "
        "should be decoded and audited, or the skill should be rejected. Remove "
        "any bidirectional control characters; ordinary Arabic and Hebrew text "
        "does not need them."
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
]
