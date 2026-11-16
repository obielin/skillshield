"""Discover and scan AI agent skills already installed on this computer."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from skillshield.models import BatchScanReport, SkillScanResult, missing_source_note
from skillshield.scanner import (
    COMPILED_PYTHON_EXTENSIONS,
    SKILL_EXTENSIONS,
    SkillScanner,
    _dir_is_skipped,
    _is_agent_rule_file,
    _is_tool_listing_file,
)

# Module-level so tests can override it without touching the host's /etc/codex/skills.
_SYSTEM_CODEX_SKILLS = Path("/etc/codex/skills")

_LEVEL_PRIORITY = {
    "ERROR": 5,
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "SAFE": 0,
}


@dataclass(frozen=True)
class InstalledLocation:
    """A candidate directory where an agent stores installed skills."""

    agent: str
    path: Path
    display: str
    scope_rank: int  # 2=project/repo, 1=user home, 0=system
    is_plugins_dir: bool = False
    skill_count: int = 0


@dataclass
class InstalledSkillEntry:
    """A single scanned file attributed to an agent, location, and skill."""

    location_index: int
    skill_key: tuple[int, str, str]
    skill_name: str
    result: SkillScanResult


@dataclass
class InstalledScanReport:
    """Result of scanning all installed agent skill locations."""

    locations: list[InstalledLocation]
    entries: list[InstalledSkillEntry]
    report: BatchScanReport

    @property
    def skill_count(self) -> int:
        return len({entry.skill_key for entry in self.entries})


@dataclass
class _CandidateFile:
    location_index: int
    location: InstalledLocation
    skill_root: Path
    skill_name: str
    entry_path: Path
    entry_suffix: str
    resolved_path: Path
    is_compiled: bool
    priority: tuple[bool, bool, int, int, int]


@dataclass
class _DiscoveryError:
    """A directory that could not be read, so the scan cannot vouch for it."""

    location_index: int
    location: InstalledLocation
    skill_root: Path
    path: Path
    message: str


def _codex_project_dirs(cwd: Path) -> list[Path]:
    """Return .agents/skills folders from ``cwd`` up to the git repo root.

    Outside a git repository only ``cwd/.agents/skills`` is checked so a scan
    never wanders into unrelated ancestor directories.
    """
    ancestors = [cwd, *cwd.parents]
    chain: list[Path] = []
    found_git = False
    for directory in ancestors:
        chain.append(directory)
        if (directory / ".git").exists():
            found_git = True
            break
    if not found_git:
        chain = [cwd]
    return [directory / ".agents" / "skills" for directory in chain]


def _relative_display(path: Path, cwd: Path) -> str:
    rel = os.path.relpath(path, cwd).replace("\\", "/")
    return rel


def discover_locations(
    home: Path | None = None,
    cwd: Path | None = None,
) -> list[InstalledLocation]:
    """Return the ordered list of agent skill locations to check."""
    resolved_home = (home or Path.home()).expanduser()
    resolved_cwd = (cwd or Path.cwd()).expanduser()

    candidates: list[InstalledLocation] = [
        InstalledLocation(
            agent="Claude Code",
            path=resolved_home / ".claude" / "skills",
            display="~/.claude/skills",
            scope_rank=1,
        ),
        InstalledLocation(
            agent="Claude Code",
            path=resolved_cwd / ".claude" / "skills",
            display=".claude/skills",
            scope_rank=2,
        ),
        InstalledLocation(
            agent="Claude Code",
            path=resolved_home / ".claude" / "plugins",
            display="~/.claude/plugins",
            scope_rank=1,
            is_plugins_dir=True,
        ),
        InstalledLocation(
            agent="Codex",
            path=resolved_home / ".agents" / "skills",
            display="~/.agents/skills",
            scope_rank=1,
        ),
    ]

    for project_dir in _codex_project_dirs(resolved_cwd):
        candidates.append(
            InstalledLocation(
                agent="Codex",
                path=project_dir,
                display=_relative_display(project_dir, resolved_cwd),
                scope_rank=2,
            )
        )

    if os.name != "nt":
        candidates.append(
            InstalledLocation(
                agent="Codex",
                path=_SYSTEM_CODEX_SKILLS,
                display=str(_SYSTEM_CODEX_SKILLS),
                scope_rank=0,
            )
        )

    candidates.extend(
        [
            InstalledLocation(
                agent="Codex",
                path=resolved_home / ".codex" / "skills",
                display="~/.codex/skills",
                scope_rank=1,
            ),
            InstalledLocation(
                agent="OpenCode",
                path=resolved_home / ".config" / "opencode" / "skills",
                display="~/.config/opencode/skills",
                scope_rank=1,
            ),
            InstalledLocation(
                agent="OpenCode",
                path=resolved_cwd / ".opencode" / "skills",
                display=".opencode/skills",
                scope_rank=2,
            ),
            InstalledLocation(
                agent="OpenClaw",
                path=resolved_home / ".openclaw" / "skills",
                display="~/.openclaw/skills",
                scope_rank=1,
            ),
            InstalledLocation(
                agent="OpenClaw",
                path=resolved_cwd / "skills",
                display="skills",
                scope_rank=2,
            ),
        ]
    )

    # Deduplicate exact-same normalized paths (e.g. when cwd == home).
    unique: list[InstalledLocation] = []
    seen_paths: set[str] = set()
    for loc in candidates:
        norm = os.path.normcase(os.path.abspath(loc.path))
        if norm in seen_paths:
            continue
        seen_paths.add(norm)
        unique.append(loc)
    return unique


def _stat_dir(path: Path) -> tuple[bool, str]:
    """Whether ``path`` is a directory, and why it could not be read if it is not.

    A path that does not exist is a missing location and stays quiet: it returns
    ``(False, "")``. Any other failure (a permission error, say) returns the
    message, because the scan cannot vouch for a directory it could not open.
    """
    try:
        st = os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False, ""
    except OSError as exc:
        return False, str(exc)
    return stat.S_ISDIR(st.st_mode), "" if stat.S_ISDIR(st.st_mode) else "not a directory"


def _find_skills_subdirs(root: Path) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Walk ``root`` following symlinks (cycle-safe) and return ``skills`` dirs.

    Returns the directories found and the ``(path, message)`` pairs for any
    directory that could not be read.
    """
    is_dir, problem = _stat_dir(root)
    if problem:
        return [], [(root, problem)]
    if not is_dir:
        return [], []

    try:
        root_stat = os.stat(root)
    except OSError as exc:
        return [], [(root, str(exc))]

    visited: set[tuple[int, int]] = {(root_stat.st_dev, root_stat.st_ino)}
    found: list[Path] = []
    errors: list[tuple[Path, str]] = []

    def _walk(directory: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError as exc:
            errors.append((directory, str(exc)))
            return
        for entry in entries:
            try:
                st = os.stat(entry.path)
            except (FileNotFoundError, NotADirectoryError):
                # A broken or dangling link names no skills directory.
                continue
            except OSError as exc:
                errors.append((Path(entry.path), str(exc)))
                continue
            if not stat.S_ISDIR(st.st_mode):
                continue
            entry_path = Path(entry.path)
            if _dir_is_skipped(entry_path):
                continue
            key = (st.st_dev, st.st_ino)
            if key in visited:
                continue
            visited.add(key)
            if entry.name == "skills":
                found.append(entry_path)
                # Do not descend further: the skill scan walks this directory itself.
                continue
            _walk(entry_path)

    _walk(root)
    return found, errors


def _extract_install_paths(installed_json: Path) -> list[Path] | None:
    """Read plugin ``installPath`` directories from Claude's ``installed_plugins.json``."""
    try:
        data = json.loads(installed_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        # A malformed inventory falls back to walking the plugins directory, so
        # an unrelated agent still gets scanned.
        return None
    if not isinstance(data, dict):
        return None
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return None

    paths: list[Path] = []
    for entry in plugins.values():
        items = entry if isinstance(entry, list) else [entry]
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("installPath"), str):
                paths.append(Path(item["installPath"]).expanduser())
    return paths


def _claude_plugin_skill_roots(plugins_dir: Path) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Find ``skills`` folders inside installed Claude Code plugins.

    Returns the roots and the ``(path, message)`` pairs for any directory that
    could not be read.
    """
    is_dir, problem = _stat_dir(plugins_dir)
    if problem:
        return [], [(plugins_dir, problem)]
    if not is_dir:
        return [], []

    installed_json = plugins_dir / "installed_plugins.json"
    roots: list[Path] = []
    errors: list[tuple[Path, str]] = []
    if installed_json.is_file():
        install_paths = _extract_install_paths(installed_json)
        if install_paths is not None:
            for install_path in install_paths:
                skills_dir = install_path / "skills"
                if skills_dir.is_dir():
                    roots.append(skills_dir)
                else:
                    found, failed = _find_skills_subdirs(install_path)
                    roots.extend(found)
                    errors.extend(failed)
            return _dedupe_dirs_by_inode(roots), errors

    found, failed = _find_skills_subdirs(plugins_dir)
    roots.extend(found)
    errors.extend(failed)
    return _dedupe_dirs_by_inode(roots), errors


def _dedupe_dirs_by_inode(dirs: list[Path]) -> list[Path]:
    seen: set[tuple[int, int]] = set()
    unique: list[Path] = []
    for directory in dirs:
        try:
            st = os.stat(directory)
        except OSError:
            continue
        if not stat.S_ISDIR(st.st_mode):
            continue
        key = (st.st_dev, st.st_ino)
        if key in seen:
            continue
        seen.add(key)
        unique.append(directory)
    return unique


def _walk_files(root: Path) -> tuple[list[tuple[Path, Path, bool]], list[tuple[Path, str]]]:
    """Return files and unreadable directories under ``root``.

    Files are ``(entry_path, resolved_path, via_symlink)``. Symbolic links are
    followed with cycle protection keyed by ``(st_dev, st_ino)``; a directory
    that cannot be opened is returned as ``(path, message)`` instead of being
    dropped, so the report can say the scan is incomplete.
    """
    is_dir, problem = _stat_dir(root)
    if problem:
        return [], [(root, problem)]
    if not is_dir:
        return [], []

    try:
        root_stat = os.stat(root)
    except OSError as exc:
        return [], [(root, str(exc))]

    visited_dirs: set[tuple[int, int]] = {(root_stat.st_dev, root_stat.st_ino)}
    collected: list[tuple[Path, Path, bool]] = []
    errors: list[tuple[Path, str]] = []

    def _walk(directory: Path, via_symlink: bool) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError as exc:
            errors.append((directory, str(exc)))
            return
        for entry in entries:
            entry_via_symlink = via_symlink or entry.is_symlink()
            try:
                st = os.stat(entry.path)
            except (FileNotFoundError, NotADirectoryError):
                # A broken or dangling link names no file to scan.
                continue
            except OSError as exc:
                errors.append((Path(entry.path), str(exc)))
                continue
            entry_path = Path(entry.path)
            if stat.S_ISDIR(st.st_mode):
                key = (st.st_dev, st.st_ino)
                if key in visited_dirs:
                    continue
                visited_dirs.add(key)
                _walk(entry_path, entry_via_symlink)
            elif stat.S_ISREG(st.st_mode):
                try:
                    resolved = entry_path.resolve()
                except OSError:
                    resolved = Path(os.path.abspath(entry_path))
                collected.append((entry_path, resolved, entry_via_symlink))

    _walk(root, root.is_symlink())
    return collected, errors


def scan_installed(
    scanner: SkillScanner | None = None,
    home: Path | None = None,
    cwd: Path | None = None,
    extensions: set[str] | None = None,
) -> InstalledScanReport:
    """Discover and scan installed skills across known coding agents."""
    active_scanner = scanner or SkillScanner()
    exts = extensions or SKILL_EXTENSIONS
    locations = discover_locations(home=home, cwd=cwd)

    chosen_files: dict[Path, _CandidateFile] = {}
    chosen_unscanned: set[Path] = set()
    discovery_errors: list[_DiscoveryError] = []

    for loc_idx, loc in enumerate(locations):
        if loc.is_plugins_dir:
            roots, failed = _claude_plugin_skill_roots(loc.path)
        else:
            is_dir, problem = _stat_dir(loc.path)
            roots = [loc.path] if is_dir else []
            failed = [(loc.path, problem)] if problem else []
        for path, message in failed:
            discovery_errors.append(
                _DiscoveryError(
                    location_index=loc_idx,
                    location=loc,
                    skill_root=loc.path,
                    path=path,
                    message=message,
                )
            )

        for skill_root in roots:
            walked, failed = _walk_files(skill_root)
            for path, message in failed:
                discovery_errors.append(
                    _DiscoveryError(
                        location_index=loc_idx,
                        location=loc,
                        skill_root=skill_root,
                        path=path,
                        message=message,
                    )
                )
            for entry_path, resolved_path, via_symlink in walked:
                entry_ext = entry_path.suffix.lower()
                resolved_ext = resolved_path.suffix.lower()
                # Compiled Python wins over a text suffix: a skill can ship a
                # payload.pyc symlink pointing at a .txt file, and reading it as
                # text would hide the bytecode the agent would actually run.
                is_compiled = (
                    entry_ext in COMPILED_PYTHON_EXTENSIONS
                    or resolved_ext in COMPILED_PYTHON_EXTENSIONS
                )
                is_scannable = not is_compiled and (
                    entry_ext in exts
                    or resolved_ext in exts
                    or _is_agent_rule_file(entry_path)
                    or _is_agent_rule_file(resolved_path)
                    or _is_tool_listing_file(resolved_path)
                )

                if not is_scannable and not is_compiled:
                    chosen_unscanned.add(resolved_path)
                    continue

                rel = entry_path.relative_to(skill_root)
                skill_name = rel.parts[0] if len(rel.parts) > 1 else rel.name
                priority = (
                    is_compiled,
                    not via_symlink,
                    loc.scope_rank,
                    len(skill_root.parts),
                    -loc_idx,
                )
                existing = chosen_files.get(resolved_path)
                if existing is None or priority > existing.priority:
                    chosen_files[resolved_path] = _CandidateFile(
                        location_index=loc_idx,
                        location=loc,
                        skill_root=skill_root,
                        skill_name=skill_name,
                        entry_path=entry_path,
                        entry_suffix=entry_ext,
                        resolved_path=resolved_path,
                        is_compiled=is_compiled,
                        priority=priority,
                    )

    # Order deterministically by location order, skill name, and resolved path.
    ordered = sorted(
        chosen_files.values(),
        key=lambda item: (item.location_index, item.skill_name, str(item.resolved_path)),
    )

    skills_per_location: dict[int, set[tuple[str, str]]] = {}
    for item in ordered:
        skills_per_location.setdefault(item.location_index, set()).add(
            (str(item.skill_root), item.skill_name)
        )

    counted_locations = [
        InstalledLocation(
            agent=loc.agent,
            path=loc.path,
            display=loc.display,
            scope_rank=loc.scope_rank,
            is_plugins_dir=loc.is_plugins_dir,
            skill_count=len(skills_per_location.get(idx, ())),
        )
        for idx, loc in enumerate(locations)
    ]

    entries: list[InstalledSkillEntry] = []
    results: list[SkillScanResult] = []
    for item in ordered:
        if item.is_compiled:
            # Name the file the agent ships when the compiled suffix is on the
            # entry itself, so a payload.pyc alias is reported as such and its
            # source is looked for beside it, not beside a text target.
            scan_target = (
                item.entry_path
                if item.entry_suffix in COMPILED_PYTHON_EXTENSIONS
                else item.resolved_path
            )
        else:
            scan_target = item.resolved_path
        active_scanner._log(
            f"  Scanning {scan_target} ({item.location.agent}: {item.skill_name})..."
        )
        if item.is_compiled:
            result = active_scanner._scan_compiled_file(scan_target)
        else:
            result = active_scanner.scan_file(scan_target)
        result.agent = item.location.agent
        result.file_path = str(scan_target)
        result.skill_name = item.skill_name
        skill_key = (item.location_index, str(item.skill_root), item.skill_name)
        entries.append(
            InstalledSkillEntry(
                location_index=item.location_index,
                skill_key=skill_key,
                skill_name=item.skill_name,
                result=result,
            )
        )
        results.append(result)

    seen_errors: set[str] = set()
    for failure in discovery_errors:
        key = os.path.normcase(os.path.abspath(failure.path))
        if key in seen_errors:
            continue
        seen_errors.add(key)
        try:
            rel = failure.path.relative_to(failure.skill_root)
            skill_name = rel.parts[0] if len(rel.parts) > 1 else rel.name
        except ValueError:
            skill_name = failure.path.name or str(failure.path)
        result = SkillScanResult(
            skill_name=skill_name,
            findings=[],
            risk_score=0.0,
            risk_level="ERROR",
            error=f"cannot read {failure.path}: {failure.message}",
            agent=failure.location.agent,
            file_path=str(failure.path),
        )
        skill_key = (failure.location_index, str(failure.skill_root), skill_name)
        entries.append(
            InstalledSkillEntry(
                location_index=failure.location_index,
                skill_key=skill_key,
                skill_name=skill_name,
                result=result,
            )
        )
        results.append(result)

    unscanned = sorted(str(p) for p in chosen_unscanned if p not in chosen_files)
    metadata: dict[str, object] = {
        "locations": [
            {
                "agent": loc.agent,
                "path": str(loc.path),
                "display": loc.display,
                "skills": loc.skill_count,
            }
            for loc in counted_locations
        ]
    }
    if unscanned:
        metadata["unscanned"] = unscanned

    batch = BatchScanReport(results=results, metadata=metadata)
    return InstalledScanReport(locations=counted_locations, entries=entries, report=batch)


def _worst_level(results: list[SkillScanResult]) -> str:
    return max(
        (r.risk_level for r in results),
        key=lambda lvl: _LEVEL_PRIORITY.get(lvl, -1),
        default="SAFE",
    )


def format_installed_text(
    installed: InstalledScanReport,
    verbose: bool = False,
    color_fn: Callable[[str, str], str] | None = None,
) -> str:
    """Format an InstalledScanReport for terminal output."""

    def paint(text: str, level: str) -> str:
        return color_fn(text, level) if color_fn is not None else text

    loc_parts = [
        f"{loc.display} ({loc.skill_count} {'skill' if loc.skill_count == 1 else 'skills'})"
        for loc in installed.locations
    ]
    report = installed.report
    lines = [
        f"Checked: {', '.join(loc_parts)}",
        "",
        "=" * 64,
        "  SKILLSHIELD -- INSTALLED SKILLS SCAN REPORT",
        "=" * 64,
        f"  Skills found:     {installed.skill_count}",
        f"  Files scanned:    {report.total_scanned}",
        f"  Safe:             {report.safe_count}",
        f"  Flagged:          {report.flagged_count}",
        f"  Critical:         {report.critical_count}",
        f"  Unreadable:       {report.error_count}",
        "-" * 64,
    ]

    if installed.skill_count == 0:
        lines.append("  No installed skills found.")
    else:
        by_agent: dict[str, dict[tuple[int, str, str], list[InstalledSkillEntry]]] = {}
        for entry in installed.entries:
            agent_groups = by_agent.setdefault(entry.result.agent, {})
            agent_groups.setdefault(entry.skill_key, []).append(entry)

        for agent, skills in by_agent.items():
            lines.append(f"  {paint(agent, 'BOLD')}")
            for skill_entries in skills.values():
                skill_name = skill_entries[0].skill_name
                skill_results = [e.result for e in skill_entries]
                worst = _worst_level(skill_results)
                lines.append(f"    {paint(f'[{worst}]', worst)} {paint(skill_name, 'BOLD')}")
                for res in skill_results:
                    if res.risk_level == "ERROR":
                        lines.append(f"      {res.file_path}: {res.error}")
                    elif res.is_safe:
                        lines.append(f"      {res.file_path} ({paint('SAFE', 'SAFE')})")
                    else:
                        lines.append(
                            f"      {res.file_path} "
                            f"({paint(res.risk_level, res.risk_level)}, score={res.risk_score:.0f})"
                        )
                    for finding in res.findings:
                        sev = finding.severity.value.upper()
                        lines.append(
                            f"        -> {paint(f'[{finding.rule_id}] {finding.name}', sev)}"
                        )
                        if verbose and finding.snippets:
                            display = finding.snippets[0][:120].replace("\n", " ")
                            lines.append(f"           Matched: ...{display}...")
                        if verbose and finding.line_numbers:
                            lines.append(f"           Lines: {finding.line_numbers[:5]}")
                    note = missing_source_note(res)
                    if note:
                        lines.append(f"        -> {note}")

    unscanned = report.metadata.get("unscanned") or []
    if unscanned:
        lines.append(f"  UNSCANNED ({len(unscanned)})")
        for path in unscanned:
            lines.append(f"    {path}")

    lines.append("=" * 64)
    return "\n".join(lines)
