# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Changed

- The GitHub Action now includes findings on unreadable files (such as malformed MCP tool listings) in `risk-level`, annotations, and the job summary (#146).
- The README explains choosing a version of the GitHub Action: `@v1` gets each new 1.x release, a pinned release such as `@v1.4.0` stays fixed, and `fail-on: none` tries a release without failing the build.

## [1.4.0]

### Upgrade notes

Some changes can make a scan fail where it passed before:

- At the default threshold (`--fail-on high`), a directory scan exits 1 when any file is CRITICAL or HIGH, as a single-file scan does. Before, a folder whose only problem was HIGH exited 0 (#83, by @ShahadatTest).
- Many more attacks are caught, several of them at CRITICAL or HIGH: instruction overrides in eleven more languages, `curl ... | bash`, code run from decoded data, a skill told to replace itself with downloaded content, text hidden in Unicode tag characters or emoji variation selectors, and Base64 payloads. A skill that tells its users to install with `curl ... | bash` is now flagged CRITICAL.
- More files are scanned: Cursor, Windsurf, Cline, Roo Code and Zed rule files, and saved MCP tool listings. A malformed tool listing is reported as unreadable and exits 2.
- Three OWASP tags changed: SG-003 adds `owasp-asi05`, SG-007 moves from `owasp-asi05` to `owasp-asi03`, and SG-010 moves from `owasp-asi04` to `owasp-asi09`. If you filter findings by tag, check your filters.

After reviewing a finding you trust, accept it with a reason in a `.skillshield-ignore` file, which is new in this release.

### Added

**Checking skills you have, and keeping track of them**

- `skillshield scan --installed` finds and scans the skills already installed for Claude Code, Codex, OpenCode and OpenClaw, and groups the report by agent and skill. A folder that exists but cannot be read is reported, so an incomplete scan cannot look clean (#92, by @JoaoSilvaIT).
- `skillshield scan https://github.com/owner/repo` scans a repository, branch or subfolder before you install it. The archive is downloaded to a temporary folder with size, file-count and path-safety limits, and deleted afterwards (#100, by @mafujahmedridoy22-commits).
- `skillshield lock skills/` writes `skillshield.lock`, with a SHA-256 hash of every file in each skill and its risk level at lock time. Locking again gives a byte-identical file when nothing changed (#174, by @seung-waedet).
- `.skillshield-ignore` accepts a reviewed finding with a required reason: by rule ID and path glob, or by the finding's fingerprint. Accepted findings leave the score and exit code but are still counted, listed with `--show-accepted`, and kept in SARIF as suppressions. A rule entry cannot accept a CRITICAL finding, and on the command line the file is only read with `--ignore-file`, so a downloaded skill cannot accept its own findings. `skillshield accept` writes fingerprints for the current findings (#101).
- `skillshield scan --fail-on` sets the failing threshold (`critical`, `high`, `medium`, `low` or `none`), as the Action already could (#173, by @pear1-pea).

**MCP tool listings**

- `skillshield scan` recognises saved MCP tool listings (a JSON manifest, a `tools/list` response or a `.jsonl` file) and checks each tool, reporting findings on the line where the tool starts. The text rules still run on the raw file (#138).
- SG-103, Unrestricted Path Parameter (HIGH): a filesystem path parameter with no `pattern` or `enum` of its own (#137, by @kushaldave002).
- SG-104, Suspicious Tool Name (HIGH): a tool named, for example, `harvest_credentials` or `exfiltrate_data` (#138, by @jay23606).
- SG-105, Tool with No Description or Input Schema (MEDIUM) (#139, by @jay23606).
- SG-106, Excessive Tool Count (LOW): a server with more than 50 tools (#140, by @kushaldave002).
- Defanged example listings in `tests/fixtures/mcp/`: three safe servers and one malicious listing per MCP rule (#141, by @ununto).

**Prompt injection in more languages (SG-001)**

Each language has its own phrase list, leaves negated and merely descriptive sentences alone, and is skipped quickly on text it cannot match, so English files scan about as fast as before.

- Chinese (Simplified and Traditional) and Japanese (#66, by @ppcvote), and Korean (#122, by @ppcvote).
- French (#115), Spanish (#116), Portuguese (#118), German (#117), Arabic (#121) and Hindi, in Devanagari and in Latin letters (#123), by @MaxonT.
- Italian (#119, by @mrCabez).
- Russian (#120, by @pear1-pea).

**More attacks caught**

- SG-006 flags a script downloaded with `curl` or `wget` and piped into a shell, including `bash <(curl ...)`, `sh -c "$(curl ...)"` and `eval "$(wget ...)"`. A file saved with `curl -o`, a lookup such as `command -v curl`, or a file whose name contains "curl" is not flagged (#30, by @matheussilvano).
- SG-006 flags `exec`, `eval` or `compile` run on data decoded in the same call (`b64decode`, `bytes.fromhex`, rot13, `zlib.decompress`, `marshal.loads`, `atob` and more), however short the payload (#105, by @sarankumar1325).
- SG-006 flags an instruction to download content and replace this skill with it. An ordinary edit, a "how to" description and a negated instruction are not flagged (#35, by @joelabarbera).
- SG-004 flags a named human persona ("You are Sarah, a human support agent") and an instruction to deny being an AI when asked (#34, by @erSpell).
- SG-002 flags code that sends the whole environment (`dict(os.environ)`, `JSON.stringify(process.env)`) over HTTP (#33, by @matheussilvano).
- SG-008 flags Unicode tag characters (ASCII smuggling), and the text hidden in them is decoded and scanned with every rule (#54, by @matheussilvano).
- SG-008 flags runs of invisible emoji variation selectors, which can carry hidden bytes (#107, by @jay23606).
- Base64 text is decoded and read with the text rules, so an instruction hidden in an encoded payload is found. A payload over the size limit marks the scan incomplete, with a warning in text and JSON output and in the Action (#29, by @Neeraj111010).

**Output and the command line**

- Directory scans include Cursor `.mdc` rules, `.clinerules/` contents, extensionless Cursor, Windsurf and Cline rules, and Roo Code and Zed instruction files (#124, by @arpanjot-coding).
- `scan` and `check` honour `NO_COLOR` and accept `--no-color` (#110, by @arpanjot-coding).
- `skillshield rules --format json` exports the rule metadata (#111, by @arpanjot-coding).
- JSON output includes each finding's `tags`, so findings can be filtered by OWASP risk.

### Changed

- Every rule is tagged with the OWASP Top 10 for Agentic Applications and the OWASP Agentic Skills Top 10, and the README maps each rule to both.
- SG-001 and SG-011 are faster on large files: SG-011 checks file and network access first (#144, by @cardtable), and the French, Spanish, Portuguese and German checks search a lowercase copy of the text (part of #144). `tests/bench_large_files.py` times each rule on large inputs.
- The README's test badge is GitHub's live CI status (#108, by @Noblesse013), and the README explains how to scan MCP tool listings (#142, by @duy-dev-26).

### Fixed

- SG-003 only flags explicit requests for elevated system privileges, not routine support escalation or admin-access wording (#8, by @arpanjot-coding).
- Findings from multiline and repeated matches report every starting line in text, JSON and SARIF output (#9, by @Mr-Neutr0n).
- SG-013 recognises `pip install -i` on versioned, quoted, escaped and Windows pip paths, such as `pip3.12`, `"/opt/my env/bin/pip"`, `/usr/bin/\pip` and `C:\Python312\Scripts\pip`, and a later `curl -i` is never read as pip's `-i` (by @arin30).
- SG-001 no longer flags a negated Chinese instruction when the negation carries a phrase such as "under any circumstances" before the verb (#99, by @shounakjoshi88-a11y).
- SG-008 keeps decoded variation-selector bytes in order when the snippet is cut short (#132, by @jay23606).
- `skillshield scan -` reads stdin as UTF-8, as a file is read. On Windows, a skill piped in with Chinese or Japanese text could scan as SAFE (by @ppcvote).
- A text report no longer stops with `UnicodeEncodeError` when stdout cannot encode a file name or snippet; before, the exit code of 1 read as a CRITICAL or HIGH result (by @ppcvote).
- A test covers the 50-snippet cap on line-number lookups (#112, by @Noblesse013).

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
