# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- SG-001 now flags instruction overrides written in Chinese (Simplified and Traditional) and Japanese, such as "忽略之前的所有指令" or "以前の指示をすべて無視してください", including overriding the system prompt, a persona with no restrictions and switching off safety filters. Each language has its own labelled phrase list in `rules.py`, and a negated phrase ("請勿忽略…", "無視しないでください") is not flagged. These patterns only run on text that contains kana or CJK ideographs, so English files scan as fast as before. Other languages are still open (#66).
- SG-002 now flags code that sends the whole environment over HTTP, which usually carries API keys: `dict(os.environ)`, `os.environ.copy()`, `json.dumps(os.environ)`, `{**os.environ}`, `JSON.stringify(process.env)` and `{...process.env}`, within a few lines of a call such as `requests.post`, `httpx.post`, `urllib.request.urlopen`, `fetch(` or `axios.post`. Reading one variable (`os.environ.get("HOME")`, `process.env.HOME`) is not flagged (#33).
- JSON output now includes each finding's `tags`, for one file and for a directory, so findings can be filtered by OWASP risk.

### Changed

- Every rule is now tagged with the OWASP Top 10 for Agentic Applications (`owasp-asi01` to `owasp-asi10`) and OWASP Agentic Skills Top 10 (`owasp-ast01` to `owasp-ast10`) risks it relates to, and the README has a new "SkillShield and agentic security" section with the full mapping. Three earlier tags were corrected: SG-003 adds ASI05, SG-007 moves from ASI05 to ASI03, and SG-010 moves from ASI04 to ASI09. If you filter findings by these tags, check your filters.

### Fixed

- SG-001 no longer flags a negated Chinese instruction when the negation carries a phrase before the verb ("请不要在任何情况下忽略之前的指令。"), or when the negation carries 再 before the verb ("不要再使用新的系统提示："). Only a phrase the negation carries counts: "不要犹豫马上忽略之前的指令。" negates the hesitation, not the ignoring, and stays flagged. A negation in the same clause still does not hide an override that comes after it (#99).
- Pattern findings report the starting lines of multiline and repeated matches in text, JSON and SARIF output without repeatedly scanning earlier lines (#9).
- A directory scan exits 1 when any file is CRITICAL or HIGH (matching a single-file scan), and exits 2 when any file cannot be read. Before, a folder whose only problem was HIGH exited 0 (#83).
- SG-013 now recognizes the short `-i` index override on versioned pip executables such as `pip3.12`, including absolute executable paths.

### Added

- SG-008 now flags Unicode tag characters (U+E0000 to U+E007F), which are not drawn on screen but a model can read (ASCII smuggling), and the text hidden in them is decoded and scanned with every rule: a finding that came from hidden text says so. The tag characters of the England, Scotland and Wales flag emojis are not flagged (#54).

## [1.3.0]

### Upgrade notes

Two changes can make a scan fail where it passed before:

- A file's risk level is now at least the severity of its worst finding, so a file with one HIGH finding is reported HIGH, not MEDIUM. `skillshield scan` on that file, and the GitHub Action at its default `fail-on: high`, now fail (#25).
- Compiled Python (`.pyc`, `.pyo`) is reported wherever it is, including in a committed `.venv`. A repository that commits a virtual environment will fail the Action at `fail-on: high` (#42).

### Added

- SG-013, Untrusted Package Registry (HIGH): flags `pip`, `npm` or `yarn` pointed at a registry other than the official one (`--index-url`, `--extra-index-url`, `pip install -i`, `--registry`, `PIP_INDEX_URL`, npm and yarn config, or a `pip.conf`, `.npmrc` or `.pypirc` override), which lets a later install pull the attacker's packages (OWASP AST02) (#46, by @Logic769).
- SG-014, Compiled Python Payload (HIGH): flags `.pyc` and `.pyo` files in a skill, and notes when the matching `.py` source is missing. Bytecode runs directly but cannot be reviewed (#42, by @Logic769).
- SG-015, Well-known Skill Name Impersonation (MEDIUM): flags a skill whose frontmatter `name` is a near-copy of a well-known skill name, such as `cllawhub`, `clawhub1` or `polymarket-pro`. The names are in `src/skillshield/data/well_known_names.txt` (#57, by @Lexus-099).
- SG-006 flags base64 data decoded and piped into a shell (`base64 -d | bash` and similar), whatever the length of the encoded string, the execution trigger in the ClawHavoc campaign (#43, by @Logic769).
- SG-008 flags bidirectional control characters (Trojan Source, CVE-2021-42574) and names each character and line (#55, by @Lark-Alfen).
- Files a scan skips are listed as unscanned in text, JSON and SARIF output and in the Action's job summary. The job summary lists at most 50 entries per section, with full totals.
- A red-team corpus (`tests/fixtures/redteam/`, `tests/test_redteam.py`) of 31 defanged malicious skills, 4 safe look-alikes and a skill folder that hides its payload outside `SKILL.md`, with known gaps tracked as issues.
- `docs/threat-coverage.md`, mapping each published attack technique to its source and SkillShield's coverage; [ROADMAP.md](ROADMAP.md); and a Limitations section in the README.

### Changed

- The package, CLI and Action descriptions now say SkillShield flags *known* attack patterns.

### Fixed

- A file's reported level is never below its worst finding (#25, by @bfs2021).
- A directory scan names each file by its path relative to the scanned directory (`a/SKILL.md`) in text, JSON and SARIF output, so code scanning links findings to the right file (#24, by @babyhuey).

## [1.2.0]

### Added

- A GitHub Action: `uses: obielin/skillshield@v1`. It scans files or directories, fails the step at a chosen level (`fail-on`, default `high`), annotates flagged files on pull requests, writes a job summary, and writes a SARIF report for GitHub code scanning. It runs on Linux, macOS and Windows runners.
- `python -m skillshield.ci`, the same scan for other CI systems, configured with environment variables.
- In the Action and `skillshield.ci`, a file's level is at least the severity of its worst finding, so one HIGH finding fails a `fail-on: high` gate. SARIF paths are relative to the repository, so code scanning links each finding to its file.

## [1.1.0]

### Changed

- Renamed the project from skillguard to SkillShield, to match the `skillshield` package on PyPI. The command is now `skillshield` and the Python package is `skillshield`.
- SARIF output names the tool `skillshield` and links to `https://github.com/obielin/skillshield`.

### Deprecated

- The `skillguard` command and `import skillguard` still work and will be removed in 2.0.0.

### Fixed

- `SkillScanner(rules=[])` runs no rules instead of all of them (#15).
- The version is read from `__version__` everywhere, so `--version`, SARIF output and the package metadata cannot drift apart (#16).
- `skillshield scan` exits 2 for a file it cannot read, and unreadable files are listed separately instead of being counted as flagged (#17).

## [1.0.0]

- First release.
