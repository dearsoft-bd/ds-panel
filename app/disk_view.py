"""What disk capacity an account is shown.

"real" (default, and always for the Super Admin): the root filesystem's
actual size/used/free.

"quota" and "custom" (set per Admin in Role Manager) both show the account
a Super-Admin-chosen total (disk_quota_gb) and only its OWN usage — the
combined size of its assigned sites' document roots, or the real used
figure for an account that isn't site-restricted — so free space reads as
"total minus mine", and the server's real size is never shown to it.
  - quota: a real allocation. File Manager refuses uploads/unzips/pastes
    that would take the account past it (see quota_exceeded).
  - custom: masked, display only — for accounts the Super Admin considers
    risky. Nothing is reserved or capped.
Anything with shell access could still read the real numbers (Terminal is
never given to a site-restricted account).
"""
import os
import shutil
import time

from flask import session

from .permissions import parse_ids

_CACHE_TTL = 300
_size_cache = {}  # document_root -> (computed_at, bytes)


def _gb(num_bytes: int) -> float:
    return round(num_bytes / (1024 ** 3), 1)


def real_disk():
    try:
        usage = shutil.disk_usage("/")
    except OSError:
        return None
    return {
        "total_gb": _gb(usage.total),
        "used_gb": _gb(usage.used),
        "free_gb": _gb(usage.free),
        "percent": round(usage.used / usage.total * 100) if usage.total else 0,
    }


def _dir_size(path: str) -> int:
    cached = _size_cache.get(path)
    if cached and time.time() - cached[0] < _CACHE_TTL:
        return cached[1]
    total = 0
    for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    _size_cache[path] = (time.time(), total)
    return total


def _own_used_bytes(db, real_used_bytes: int) -> int:
    if not session.get("site_scope"):
        return real_used_bytes
    ids = parse_ids(session["site_scope"])
    if not ids:
        return 0
    placeholders = ",".join("?" * len(ids))
    rows = db.execute(f"SELECT document_root FROM sites WHERE id IN ({placeholders})", list(ids)).fetchall()
    return sum(_dir_size(r["document_root"]) for r in rows)


def is_custom() -> bool:
    """Whether this session sees an allocated/masked disk instead of the real one."""
    return session.get("role") != "super_admin" and session.get("disk_display") in ("quota", "custom")


def invalidate() -> None:
    """Forget cached folder sizes — called after File Manager writes so the
    next quota check sees the new usage."""
    _size_cache.clear()


def quota_exceeded(db, extra_bytes: int = 0) -> bool:
    """For a "quota" session: would `extra_bytes` more take it past its
    allocation? Always False for every other mode."""
    if session.get("role") == "super_admin" or session.get("disk_display") != "quota":
        return False
    total = int(session.get("disk_quota_gb") or 0) * 1024 ** 3
    try:
        real_used = shutil.disk_usage("/").used
    except OSError:
        real_used = 0
    return _own_used_bytes(db, real_used) + max(extra_bytes, 0) > total


def apply(stats, db):
    """Rewrites the disk_* keys of a system_ops.get_system_stats() dict in
    place for a "custom" display session. No-op otherwise."""
    if not stats or not is_custom():
        return stats
    total = int(session.get("disk_quota_gb") or 0) * 1024 ** 3
    real_used = int(stats.get("disk_used_gb", 0) * 1024 ** 3)
    used = min(_own_used_bytes(db, real_used), total) if total else 0
    stats.update(
        disk_total_gb=_gb(total),
        disk_used_gb=_gb(used),
        disk_free_gb=_gb(total - used),
        disk_percent=round(used / total * 100) if total else 0,
    )
    return stats
