"""
Red-team corpus: realistic malicious skills, and safe skills that look suspicious.

Each malicious sample must be flagged at its expected severity or above, judged
by its worst finding. Each safe sample must have no findings.

Samples SkillShield does not handle yet are marked xfail(strict=True). When a
change makes one pass, pytest reports it as an unexpected pass and fails, so
remove that sample from KNOWN_GAPS or KNOWN_FALSE_POSITIVES in the same PR.
Each entry names the GitHub issue that tracks it.

All samples are defanged: they use example.com and dummy account numbers, and
contain nothing that runs. See tests/fixtures/redteam/README.md.
"""

from pathlib import Path

import pytest

from skillshield import SkillScanner
from skillshield.rules import Severity

CORPUS = Path(__file__).parent / "fixtures" / "redteam"
ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# The lowest severity each malicious sample must be flagged at.
EXPECTED = {
    "01-plain-injection": Severity.CRITICAL,
    "02-paraphrased-injection": Severity.CRITICAL,
    "03-hidden-html-comment": Severity.CRITICAL,
    "04-zero-width-split": Severity.CRITICAL,
    "05-homoglyph": Severity.CRITICAL,
    "06-base64-payload": Severity.CRITICAL,
    "07-curl-pipe-shell": Severity.CRITICAL,
    "08-natural-exfil": Severity.CRITICAL,
    "09-markdown-image-exfil": Severity.HIGH,
    "10-python-exfil": Severity.CRITICAL,
    "11-impersonation": Severity.HIGH,
    "12-rug-pull": Severity.CRITICAL,
    "13-tool-poisoning": Severity.HIGH,
    "14-delayed-trigger": Severity.HIGH,
    "15-base64-pipe-shell": Severity.CRITICAL,
    "16-fake-prerequisite-archive": Severity.HIGH,
    "17-paste-site-script": Severity.HIGH,
    "18-memory-poisoning": Severity.HIGH,
    "19-persistence-service": Severity.HIGH,
    "20-fake-system-tag": Severity.CRITICAL,
    "21-suppress-security-warnings": Severity.HIGH,
    "22-cross-tool-hijack": Severity.HIGH,
    "23-unicode-tag-smuggling": Severity.CRITICAL,
    "24-bidi-override": Severity.HIGH,
    "25-remote-instructions": Severity.HIGH,
    "26-seed-phrase-harvest": Severity.CRITICAL,
    "27-registry-hijack": Severity.HIGH,
    "28-whitespace-inflation": Severity.CRITICAL,
    "29-description-injection": Severity.CRITICAL,
    "30-non-english-injection": Severity.CRITICAL,
    "31-trifecta-reworded": Severity.CRITICAL,
}

# Malicious samples not yet flagged at their expected severity: sample -> what is missing.
KNOWN_GAPS = {
    "02-paraphrased-injection": "reworded instruction override (#28)",
    "04-zero-width-split": "text is not normalised before matching (zero-width characters) (#27)",
    "05-homoglyph": "text is not normalised before matching (lookalike letters) (#27)",
    "06-base64-payload": "base64 is flagged but its decoded content is not scanned (#29)",
    "07-curl-pipe-shell": "piping a downloaded script into a shell (#30)",
    "08-natural-exfil": "plain-English instruction to send secret files to a URL (#31)",
    "09-markdown-image-exfil": "data leaked through a markdown image URL (#32)",
    "10-python-exfil": "code that posts environment variables to a URL (#33)",
    "11-impersonation": "persona that denies being an AI (#34)",
    "12-rug-pull": "instruction to replace the skill with remote content (#35)",
    "13-tool-poisoning": "hidden side action the user is told nothing about (#36)",
    "14-delayed-trigger": "dormant instruction that fires on a trigger word (#37)",
    "16-fake-prerequisite-archive": "fake prerequisite: download a password-protected archive and run it (#44)",
    "17-paste-site-script": "install script from a paste site pasted into a terminal (#45)",
    "18-memory-poisoning": "writes instructions into agent memory files (#47)",
    "19-persistence-service": "installs a system service or cron job (#48)",
    "20-fake-system-tag": "fake <SYSTEM> tag and developer-mode framing (#49)",
    "21-suppress-security-warnings": "tells the agent to hide security findings (#50)",
    "22-cross-tool-hijack": "instruction that changes how other tools run (#51)",
    "23-unicode-tag-smuggling": "instruction hidden in invisible Unicode tag characters (#54)",
    "24-bidi-override": "right-to-left override characters hide what text says (#55)",
    "25-remote-instructions": "fetches instructions from a URL at run time and follows them (#52)",
    "26-seed-phrase-harvest": "asks for a crypto wallet recovery phrase (#53)",
    "30-non-english-injection": "instruction override in a language other than English (#66)",
    "31-trifecta-reworded": "lethal trifecta depends on the English injection phrases (#67)",
}

# Safe samples that are wrongly flagged: sample -> why it is safe.
KNOWN_FALSE_POSITIVES = {
    "b1-security-docs": "documentation that quotes an attack phrase as an example (#38)",
}


def _worst(findings) -> Severity | None:
    return max((f.severity for f in findings), key=ORDER.index, default=None)


def _samples(kind, known):
    params = []
    for path in sorted((CORPUS / kind).glob("*.md")):
        marks = []
        if path.stem in known:
            marks.append(pytest.mark.xfail(reason=known[path.stem], strict=True))
        params.append(pytest.param(path, id=path.stem, marks=marks))
    return params


def test_every_malicious_sample_has_an_expected_severity():
    stems = {p.stem for p in (CORPUS / "malicious").glob("*.md")}
    assert stems == set(EXPECTED)
    assert set(KNOWN_GAPS) <= stems


@pytest.mark.parametrize("path", _samples("malicious", KNOWN_GAPS))
def test_malicious_sample_is_flagged(path):
    result = SkillScanner().scan_file(path)
    worst = _worst(result.findings)
    expected = EXPECTED[path.stem]
    assert worst is not None, f"{path.stem}: no findings"
    assert ORDER.index(worst) >= ORDER.index(
        expected
    ), f"{path.stem}: worst finding is {worst.value}, expected {expected.value} or above"


@pytest.mark.parametrize("path", _samples("benign", KNOWN_FALSE_POSITIVES))
def test_safe_sample_is_not_flagged(path):
    result = SkillScanner().scan_file(path)
    assert result.findings == [], f"{path.stem}: {[f.rule_id for f in result.findings]}"


# Files in a skill folder that carry a payload SkillShield does not look at yet.
# Each must appear in a directory scan with a finding (or as an unscanned file
# that is reported, once that exists): file -> what is missing.
SKILL_FOLDER = CORPUS / "skill-folder"
FOLDER_GAPS = {
    "scripts/format.pyc": "compiled Python is skipped without being reported (#42)",
    "scripts/install": "script without an extension is skipped (no shebang check) (#40)",
    "scripts/setup.ps1": "PowerShell scripts are skipped (#40)",
    "helper.zip": "password-protected archive is skipped (#41)",
    "plain.zip": "archive contents are not scanned (#41)",
    "guide.docx": "document archive contents are not scanned (#41)",
}


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(name, id=name, marks=pytest.mark.xfail(reason=reason, strict=True))
        for name, reason in FOLDER_GAPS.items()
    ],
)
def test_payload_file_in_skill_folder_is_flagged(name):
    report = SkillScanner().scan_directory(SKILL_FOLDER)
    flagged = {r.skill_name for r in report.results if r.findings or r.risk_level == "ERROR"}
    assert Path(name).name in flagged, f"{name} was not flagged; flagged: {sorted(flagged)}"
