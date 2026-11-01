# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Changed

- The package, CLI and Action descriptions now say SkillShield flags *known* attack patterns, and the README points to the Limitations section and the new [ROADMAP.md](ROADMAP.md).

### Added

- A red-team corpus (`tests/fixtures/redteam/`, `tests/test_redteam.py`): 31 defanged malicious skills, one per attack technique, 4 safe skills that look suspicious, and a skill folder that hides its payload outside `SKILL.md`. Techniques SkillShield does not catch yet are tracked as known gaps.
- `docs/threat-coverage.md`: the attack techniques reported against agent skills in 2025–2026, with sources, and how far SkillShield covers each.
- A Limitations section in the README.
- SG-013, Untrusted Package Registry: flag `pip`, `npm` or `yarn` pointed at a registry other than the official one (`--index-url`, `--extra-index-url`, `-i`, `--registry`, `PIP_INDEX_URL`, npm/yarn config, or a `pip.conf`, `.npmrc` or `.pypirc` override), which lets a later install pull the attacker's packages (dependency confusion, OWASP AST02) (#46).
- SG-006 now flags base64 data decoded and piped into a shell (`base64 -d | bash` and similar), whatever the length of the encoded string (#43). The ClawHavoc campaign used this as its execution trigger.

### Fixed

- A directory scan names each file by its path relative to the scanned directory (for example `a/SKILL.md`), with forward slashes, in text, JSON and SARIF output. Before, it used the file name only, so SARIF results for several `SKILL.md` files all pointed at `SKILL.md` (#24).

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
