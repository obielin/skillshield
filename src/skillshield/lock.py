"""Record a hash of every file in each skill, and report what changed since."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
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
        # lstat, because os.replace replaces a link at that path, not the file it points to.
        info = lock_file.lstat()
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


def _is_skill_entry(entry: object) -> bool:
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("files"), dict)
        and all(isinstance(value, str) for value in entry["files"].values())
        and not any("\0" in name for name in entry["files"])
        and isinstance(entry.get("risk_level"), str)
    )


def read_lock(lock_file: Path) -> dict:
    """Read and check a lock file written by write_lock."""
    try:
        # Checked first, so a FIFO is refused instead of blocking the read.
        if not stat.S_ISREG(lock_file.stat().st_mode):
            raise LockError(f"{lock_file} is not a regular file")
        data = json.loads(lock_file.read_bytes())
    except FileNotFoundError as exc:
        raise LockError(f"{lock_file} not found; run skillshield lock first") from exc
    except OSError as exc:
        raise LockError(f"could not read {lock_file}: {exc}") from exc
    except (ValueError, RecursionError) as exc:
        raise LockError(f"{lock_file} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise LockError(f"{lock_file} is not a skillshield lock file")
    version = data.get("lock_version")
    # type() and not ==, because JSON true and 1.0 both compare equal to 1.
    if type(version) is not int or version != LOCK_VERSION:
        raise LockError(
            f"{lock_file} has lock_version {version!r}; this skillshield reads {LOCK_VERSION}"
        )
    skills = data.get("skills")
    if (
        not isinstance(skills, dict)
        or not all(map(_is_skill_entry, skills.values()))
        or any("\0" in key for key in skills)
    ):
        raise LockError(f"{lock_file} is not a skillshield lock file")
    if not isinstance(data.get("skillshield_version", ""), str):
        raise LockError(f"{lock_file} is not a skillshield lock file")
    return data


def write_lock(lock: dict, lock_file: Path) -> None:
    """Write the lock as sorted JSON, replacing any old file in one step.

    When nothing but the time would change, the previous locked_at is kept, so
    locking the same skills again gives a byte-identical file.
    """
    try:
        previous = read_lock(lock_file)
    except LockError:
        previous = None
    if previous is not None and "locked_at" in previous:
        if {**previous, "locked_at": lock["locked_at"]} == lock:
            lock = {**lock, "locked_at": previous["locked_at"]}
    data = (json.dumps(lock, indent=2, sort_keys=True) + "\n").encode("utf-8")
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = lock_file.with_name(f".{lock_file.name}.{secrets.token_hex(8)}.tmp")
    # O_EXCL refuses a file or link planted at that name. mkstemp does too, but it
    # creates the file 0600, and the lock should get the usual umask mode.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o666)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        os.replace(tmp, lock_file)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _compare_skill(locked: dict, current: dict) -> dict | None:
    old, new = locked["files"], current["files"]
    changes = {
        "added": sorted(new.keys() - old.keys()),
        "removed": sorted(old.keys() - new.keys()),
        "changed": sorted(name for name in old.keys() & new.keys() if old[name] != new[name]),
        "risk_level": {"locked": locked["risk_level"], "current": current["risk_level"]},
    }
    unchanged = locked["risk_level"] == current["risk_level"]
    if unchanged and not (changes["added"] or changes["removed"] or changes["changed"]):
        return None
    return changes


def compare_locks(locked: dict, current: dict) -> dict:
    """What changed from the locked skills to the current ones."""
    old, new = locked["skills"], current["skills"]
    skills = {}
    for key in sorted(old.keys() & new.keys()):
        changes = _compare_skill(old[key], new[key])
        if changes is not None:
            skills[key] = changes
    new_skills = sorted(new.keys() - old.keys())
    missing_skills = sorted(old.keys() - new.keys())
    return {
        "changed": bool(skills or new_skills or missing_skills),
        "missing_skills": missing_skills,
        "new_skills": new_skills,
        "skills": skills,
    }


def _is_within(path: str, directory: str) -> bool:
    path, directory = os.path.normcase(path), os.path.normcase(directory)
    try:
        return os.path.commonpath([path, directory]) == directory
    except ValueError:  # Windows: different drives
        return False


def _identity(path: str) -> tuple[int, int] | None:
    try:
        info = os.stat(path)
    except (OSError, ValueError):
        return None
    return (info.st_dev, info.st_ino) if info.st_ino else None


def _ancestors(path: str):
    while True:
        yield path
        parent = os.path.dirname(path)
        if parent == path:
            return
        path = parent


def _lock_spelling(root: str, locked_paths: list[str]) -> str:
    """root spelled the way the lock spells the same directory.

    A target reached another way, in another case or through a symbolic link,
    is then compared path by path, the same way lock wrote it. Directories are
    matched by (device, inode) and not by realpath, because two locked skills can
    be one directory under two names, and each keeps its own name.
    """
    if any(_is_within(path, root) or _is_within(root, path) for path in locked_paths):
        return root
    spellings: dict[tuple[int, int], str] = {}
    for path in sorted(locked_paths):
        for ancestor in _ancestors(path):
            identity = _identity(ancestor)
            if identity is None:
                continue
            # Two locked skills can be one directory; prefer the one that is not a link.
            known = spellings.get(identity)
            if known is None or (os.path.islink(known) and not os.path.islink(ancestor)):
                spellings[identity] = ancestor
    for ancestor in _ancestors(root):
        spelled = spellings.get(_identity(ancestor))
        if spelled is not None:
            return os.path.normpath(os.path.join(spelled, os.path.relpath(root, ancestor)))
    return root


def verify(target: Path, lock_file: Path) -> dict:
    """Lock the skills under target again and compare them with lock_file.

    Only locked skills under target are compared, so verifying one skill of a
    locked folder does not report the others as missing.
    """
    locked = read_lock(lock_file)
    lock_dir = os.path.dirname(os.path.abspath(lock_file))
    paths = {key: os.path.abspath(os.path.join(lock_dir, key)) for key in locked["skills"]}
    root = os.path.abspath(target)
    # abspath drops ".." as text, and the OS resolves it after following links.
    if _identity(root) != _identity(str(target)):
        raise LockError(f"{target} leads somewhere else once its links are followed")
    root = _lock_spelling(root, list(paths.values()))
    for key, path in paths.items():
        if _is_within(root, path) and os.path.normcase(root) != os.path.normcase(path):
            raise LockError(f"{target} is inside the locked skill {key}; verify {key} instead")
    in_target = {
        key: entry for key, entry in locked["skills"].items() if _is_within(paths[key], root)
    }
    skills = find_skills(Path(root)) if os.path.isdir(root) else []
    if not skills and not in_target:
        if not target.exists():
            raise LockError(f"{target} not found")
        raise LockError(f"no skills found in {target}, and {lock_file} has none under it")
    current = build_lock(skills, lock_file)
    report = compare_locks({"skills": in_target}, current)
    report["skillshield_version"] = {
        "current": __version__,
        "locked": locked.get("skillshield_version"),
    }
    return report
