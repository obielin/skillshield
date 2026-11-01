# Threat coverage

This page lists the attack techniques that have been reported against AI agent skills in 2025 and 2026, and how far SkillShield covers each one. Every technique has a defanged sample in [`tests/fixtures/redteam/`](../tests/fixtures/redteam/) and a test in [`tests/test_redteam.py`](../tests/test_redteam.py), so this page and the test suite cannot drift apart: a technique marked as a gap here is an expected failure there.

Status as of SkillShield 1.2.0 (October 2026):

- **Covered**: the sample is flagged at the expected severity.
- **Gap**: the sample is not flagged, or is flagged too low. The issue tracks the fix.

AST numbers refer to the [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) (v1.0, August 2026).

## Summary

| | Count |
|---|---|
| Malicious samples covered | 6 of 31 |
| Malicious samples with an open gap | 25 of 31 |
| Payload files in a skill folder covered | 0 of 6 |
| Safe samples wrongly flagged | 1 of 4 |

## Instruction override and hidden text

| Sample | Technique | AST | Source | Status |
|---|---|---|---|---|
| 01 | "Ignore all previous instructions" | AST01 | [Snyk ToxicSkills][snyk-tox] | Covered (SG-001) |
| 02 | Reworded instruction override | AST01 | [Snyk ToxicSkills][snyk-tox] | Gap: #28 |
| 03 | Instruction inside an HTML comment | AST01 | [Invariant Labs disclosure][invariant] | Covered (SG-001) |
| 04 | Zero-width characters inside words | AST08 | [Invariant Labs disclosure][invariant] | Gap: #27 |
| 05 | Lookalike letters from other alphabets | AST08 | [Invariant Labs disclosure][invariant] | Gap: #27 |
| 20 | Fake `<SYSTEM>` tag and "developer mode" | AST01 | [Snyk ToxicSkills][snyk-tox], [Invariant Labs][invariant] | Gap: #49 |
| 23 | Instruction in invisible Unicode tag characters | AST08 | [ASCII smuggling][smuggle], [Snyk ToxicSkills][snyk-tox] | Gap: #54 |
| 24 | Right-to-left override characters | AST08 | [Trojan Source, CVE-2021-42574][trojan] | Gap: #55 |
| 28 | Payload after 100,000 blank lines | AST08 | [Trail of Bits via CSA][csa] | Covered (SG-001) |
| 29 | Injection in the frontmatter `description` | AST04 | [Anthropic][anthropic] | Covered (SG-001); frontmatter checks: #56 |
| 30 | Instruction override in French (and other languages) | AST01 | Public feedback on the launch post, Oct 2026 | Gap: #66 |

## Code execution and payload delivery

| Sample | Technique | AST | Source | Status |
|---|---|---|---|---|
| 06 | Base64 payload with "decode and follow" | AST08 | [Snyk ToxicSkills][snyk-tox] | Gap: #29 (flagged, but decoded text not scanned) |
| 07 | `curl ... \| bash` | AST01 | [Snyk ToxicSkills][snyk-tox] | Gap: #30 |
| 15 | Short base64 piped into a shell | AST01 | [Snyk ClawdHub campaign][snyk-camp] | Covered (SG-006) |
| 16 | Fake prerequisite: password-protected archive, then run it | AST01 | [The Hacker News][thn], [Snyk][snyk-camp] | Gap: #44 |
| 17 | Script from a paste site, pasted into a terminal | AST01 | [The Hacker News][thn] | Gap: #45 |
| 27 | pip or npm pointed at an untrusted registry | AST02 | [Trail of Bits via CSA][csa] | Covered (SG-013) |

## Data theft

| Sample | Technique | AST | Source | Status |
|---|---|---|---|---|
| 08 | Plain-English "send ~/.ssh and .env to a URL" | AST01 | [Invariant Labs disclosure][invariant] | Gap: #31 |
| 09 | Data in a markdown image URL | AST01 | [Simon Willison on Johann Rehberger's NotebookLM finding][md-image] | Gap: #32 |
| 10 | Code that posts all environment variables | AST01 | [Trail of Bits via CSA][csa] | Gap: #33 |
| 26 | Asking for a wallet recovery phrase | AST01 | [The Hacker News][thn], [Snyk ToxicSkills][snyk-tox] | Gap: #53 |

## Persistence and drift

| Sample | Technique | AST | Source | Status |
|---|---|---|---|---|
| 12 | Replace the skill with remote content | AST07 | [OWASP][owasp] | Gap: #35 |
| 18 | Write instructions into `MEMORY.md` / `SOUL.md` | AST01 | [Snyk, SKILL.md shell access][snyk-shell] | Gap: #47 |
| 19 | System service, cron job or login item | AST01 | [Snyk ToxicSkills][snyk-tox] | Gap: #48 |
| 25 | Fetch instructions from a URL at run time | AST05 | [OWASP][owasp], [Snyk ToxicSkills][snyk-tox] | Gap: #52 |

## Manipulating the agent's behaviour

| Sample | Technique | AST | Source | Status |
|---|---|---|---|---|
| 11 | Human persona that denies being an AI | AST01 | Transparency duty in EU AI Act Article 50 | Gap: #34 |
| 13 | Hidden side action ("don't tell the user") | AST01 | [Invariant Labs disclosure][invariant] | Gap: #36 |
| 14 | Dormant instruction with a trigger word | AST01 | [Snyk, SKILL.md shell access][snyk-shell] | Gap: #37 |
| 21 | Hide or downgrade security findings | AST01 | [Trail of Bits, line jumping][tob-lj] | Gap: #50 |
| 22 | Change how other tools run | AST03 | [Trail of Bits, line jumping][tob-lj] | Gap: #51 |
| 31 | Network and file access with a reworded override (trifecta switched off) | AST01 | [Snyk ToxicSkills][snyk-tox]; public feedback, Oct 2026 | Gap: #67 |

## Payload outside SKILL.md

`tests/fixtures/redteam/skill-folder/` is one skill with a harmless `SKILL.md` and the payload in other files. A directory scan currently reports it as one SAFE file, because files with other extensions are skipped without being reported (#39).

| File | Technique | Source | Status |
|---|---|---|---|
| `scripts/format.pyc` | Compiled Python with no source | [Trail of Bits via CSA][csa] | Gap: #42 |
| `scripts/install` | Shell script with no extension | [Snyk ToxicSkills][snyk-tox] | Gap: #40 |
| `scripts/setup.ps1` | PowerShell download and run | [The Hacker News][thn] | Gap: #40 |
| `helper.zip` | Password-protected archive | [Snyk ClawdHub campaign][snyk-camp] | Gap: #41 |
| `plain.zip` | Archive with an instruction inside | [Snyk ClawdHub campaign][snyk-camp] | Gap: #41 |
| `guide.docx` | Document archive with an instruction inside | [Trail of Bits via CSA][csa] | Gap: #41 |

## False positives

| Sample | What is wrongly flagged | Status |
|---|---|---|
| b1 | Documentation that quotes an attack phrase as an example | Gap: #38 |

## Not yet covered by a sample

These are reported risks without a sample yet. Proposals for samples are welcome.

- **Typosquatted skill names** such as `clawhub1` and `cllawhub` ([The Hacker News][thn], AST04): #57.
- **Over-broad permissions** in frontmatter, such as unrestricted shell access (AST03): #56.
- **Prompt injection aimed at LLM-based scanners**, where the payload is framed as company policy ([Trail of Bits via CSA][csa]). SkillShield does not use an LLM, so this does not apply today, but any future semantic check must be tested against it.
- **Obfuscation by encryption or custom encodings** (base85 with XOR, transposition ciphers) reported in the community study summarised by [CSA][csa]. A pattern scanner cannot decode these; flagging high-entropy blobs is the realistic defence.

## Sources

- Snyk, ToxicSkills (5 February 2026). <https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub>
- Snyk, ClawdHub malicious campaign (4 February 2026). <https://snyk.io/articles/clawdhub-malicious-campaign-ai-agent-skills/>
- Snyk, SKILL.md and shell access. <https://snyk.io/articles/skill-md-shell-access/>
- The Hacker News, 341 malicious ClawHub skills (February 2026), reporting Koi Security's ClawHavoc findings. <https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html>
- Cloud Security Alliance, AI agent skill scanners: bypassed across the board (10 June 2026), summarising Trail of Bits, "The sorry state of skill distribution" (3 June 2026). <https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/>
- Trail of Bits, Jumping the line (21 April 2025). <https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/>
- PolicyLayer, Hidden instructions in tool descriptions, on Invariant Labs' disclosure (1 April 2025). <https://policylayer.com/attacks/hidden-instructions-in-tool-descriptions>
- promptfoo, ASCII smuggling. <https://promptfoo.dev/docs/red-team/plugins/ascii-smuggling/>
- Help Net Security, Trojan Source (November 2021). <https://www.helpnetsecurity.com/2021/11/02/supply-chain-attacks-source-code/>
- Anthropic, Equipping agents for the real world with Agent Skills. <https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills>
- Simon Willison, Google NotebookLM data exfiltration (16 April 2024), on Johann Rehberger's markdown image finding. <https://simonwillison.net/2024/Apr/16/google-notebooklm-data-exfiltration>
- OWASP Agentic Skills Top 10. <https://owasp.org/www-project-agentic-skills-top-10/>

[snyk-tox]: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub
[snyk-camp]: https://snyk.io/articles/clawdhub-malicious-campaign-ai-agent-skills/
[snyk-shell]: https://snyk.io/articles/skill-md-shell-access/
[thn]: https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html
[csa]: https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/
[tob-lj]: https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/
[invariant]: https://policylayer.com/attacks/hidden-instructions-in-tool-descriptions
[smuggle]: https://promptfoo.dev/docs/red-team/plugins/ascii-smuggling/
[trojan]: https://www.helpnetsecurity.com/2021/11/02/supply-chain-attacks-source-code/
[anthropic]: https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills
[md-image]: https://simonwillison.net/2024/Apr/16/google-notebooklm-data-exfiltration
[owasp]: https://owasp.org/www-project-agentic-skills-top-10/
