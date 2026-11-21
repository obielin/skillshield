"""Record a hash of every file in each skill, so later changes can be detected."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from skillshield import __version__
from skillshield.ci import _is_scanned, highest_level
from skillshield.scanner import COMPILED_PYTHON_EXTENSIONS, SkillScanner, _dir_is_skipped

LOCK_VERSION = 1
SKILL_FILE = "SKILL.md"

_CHUNK_SIZE = 1 << 20


class LockError(Exception):
    """A skill could not be locked."""


def _raise(error: OSError) -> None:
    raise error


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _has_skill_file(directory: Path) -> bool:
    # A listing, not a lookup, so SKILL.md is matched case-sensitively on every OS.
    return SKILL_FILE in os.listdir(directory)


def find_skills(target: Path) -> list[Path]:
    """Directories under target that hold a SKILL.md.

    A SKILL.md inside a skill is part of that skill, not a skill of its own. A
    symbolic link to a skill directory counts as that skill; other linked
    directories are not followed.
    """
    if _has_skill_file(target):
        return [target]
    skills = []
    for root, dirs, files in os.walk(target, onerror=_raise):
        current = Path(root)
        if current != target and SKILL_FILE in files:
            skills.append(current)
            dirs.clear()
            continue
        kept = []
        for d in dirs:
            path = current / d
            if path.is_symlink():
                if _has_skill_file(path):
                    skills.append(path)
            elif not _dir_is_skipped(path):
                kept.append(d)
        dirs[:] = kept
    return sorted(skills)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(_CHUNK_SIZE):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def lock_skill(skill: Path, scanner: SkillScanner, exclude: tuple[int, int] | None = None) -> dict:
    """The lock entry for one skill: a hash of each file and the skill's risk level.

    Files in skipped directories are left out, except compiled Python, which the
    scanner reads wherever it sits. Symbolic links are recorded by where they
    point, and linked directories are not walked. exclude is the (device, inode)
    of the lock file, left out when it sits inside the skill. The risk level comes
    from scanning the recorded files, and the files they link to, as scan does.
    """
    files: dict[str, str] = {}
    scanned = []
    skipped = {skill: False}
    for root, dirs, names in os.walk(skill, onerror=_raise):
        current = Path(root)
        in_skipped = skipped[current]
        for d in list(dirs):
            path = current / d
            if path.is_symlink():
                dirs.remove(d)
                names.append(d)
            else:
                skipped[path] = in_skipped or _dir_is_skipped(path)
        for name in names:
            path = current / name
            if in_skipped and path.suffix.lower() not in COMPILED_PYTHON_EXTENSIONS:
                continue
            info = path.lstat()
            if (info.st_dev, info.st_ino) == exclude:
                continue
            key = path.relative_to(skill).as_posix()
            if stat.S_ISLNK(info.st_mode):
                files[key] = f"symlink:{os.readlink(path).replace(os.sep, '/')}"
                if path.is_file() and _is_scanned(path, skill):
                    scanned.append(path)
            elif stat.S_ISREG(info.st_mode):
                files[key] = _hash_file(path)
                if _is_scanned(path, skill):
                    scanned.append(path)
            else:
                raise LockError(f"{path} is not a regular file, a directory or a symbolic link")
    results = [scanner.scan_file(path) for path in scanned]
    unreadable = [str(path) for path, r in zip(scanned, results) if r.risk_level == "ERROR"]
    if unreadable:
        raise LockError(f"could not scan {', '.join(unreadable)}")
    return {"files": dict(sorted(files.items())), "risk_level": highest_level(results)}


def build_lock(skills: list[Path], lock_file: Path) -> dict:
    """The lock for the given skills, with paths relative to the lock file."""
    scanner = SkillScanner()
    lock_dir = Path(os.path.abspath(lock_file)).parent
    try:
        info = lock_file.stat()
        # st_ino is only unique when it is non-zero, so 0 cannot identify the file.
        exclude = (info.st_dev, info.st_ino) if info.st_ino else None
    except FileNotFoundError:
        exclude = None
    entries = {}
    for skill in skills:
        try:
            key = Path(os.path.relpath(os.path.abspath(skill), lock_dir)).as_posix()
        except ValueError as exc:  # Windows: the skill and the lock file are on different drives
            raise LockError(f"{skill} and {lock_file} must be on the same drive") from exc
        entries[key] = lock_skill(skill, scanner, exclude)
    return {
        "lock_version": LOCK_VERSION,
        "skillshield_version": __version__,
        "locked_at": _now(),
        "skills": entries,
    }


def _previous_lock(lock_file: Path) -> dict | None:
    try:
        previous = json.loads(lock_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return previous if isinstance(previous, dict) else None


def write_lock(lock: dict, lock_file: Path) -> None:
    """Write the lock as sorted JSON, replacing any old file in one step.

    When nothing but the time would change, the previous locked_at is kept, so
    locking the same skills again gives a byte-identical file.
    """
    previous = _previous_lock(lock_file)
    if previous is not None and "locked_at" in previous:
        if {**previous, "locked_at": lock["locked_at"]} == lock:
            lock = {**lock, "locked_at": previous["locked_at"]}
    data = (json.dumps(lock, indent=2, sort_keys=True) + "\n").encode("utf-8")
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = lock_file.with_name(f".{lock_file.name}.{os.getpid()}.tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, lock_file)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
