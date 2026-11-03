# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Fixed

- SG-013 now recognizes the short `-i` index override on versioned pip executables such as `pip3.12`, including absolute executable paths.

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
