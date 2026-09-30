"""File Manager — Phase 3. Every route resolves its path through
system_ops.safe_path() before touching disk; nothing here trusts a
client-supplied path directly. Scoped entirely to SITES_ROOT
(/var/www/dearsoft-sites) — this is not a general-purpose server file
browser, only a manager for the sites this panel created.
"""
import shutil
import uuid
import zipfile
from datetime import datetime
from pathlib import Path

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, send_file, session

from . import system_ops
from .security import login_required, restricted_site_ids

bp = Blueprint("files", __name__)


def _restricted_domains() -> set | None:
    """None = this session can touch any site's files (super_admin, an
    unrestricted admin, viewer, or custom-with-files-permission). A set
    (possibly empty) = the exact top-level site folders (domains) a
    site-restricted admin may touch — see security.restricted_site_ids()
    and account.py's site_scope. Every site's document root is a single
    top-level folder directly under SITES_ROOT named after its domain
    (system_ops.document_root_for), so checking just the first path
    segment is sufficient and matches how safe_path() resolves paths.
    """
    ids = restricted_site_ids()
    if ids is None:
        return None
    if not ids:
        return set()
    placeholders = ",".join("?" * len(ids))
    rows = g.db.execute(f"SELECT domain FROM sites WHERE id IN ({placeholders})", list(ids)).fetchall()
    return {r["domain"] for r in rows}


def _path_allowed(rel_path: str, domains: set) -> bool:
    """The path must RESOLVE inside one of `domains`' folders — resolving
    first means "a.com/../b.com", or a symlink inside a.com pointing at
    b.com, is judged by where it actually lands. The sites root itself
    (an empty path) is never allowed: that listing is every site."""
    try:
        resolved = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError:
        return False
    parts = resolved.relative_to(system_ops.SITES_ROOT.resolve()).parts
    return bool(parts) and parts[0] in domains


def _trash_row_allowed(item_id, domains: set) -> bool:
    row = g.db.execute("SELECT original_rel_path FROM file_trash WHERE id = ?", (item_id,)).fetchone()
    return bool(row) and _path_allowed(row["original_rel_path"], domains)


# File Manager settings (default path, show hidden) and Empty Trash are
# panel-wide, shared by every account — never for a site-restricted admin.
_RESTRICTED_BLOCKED_ENDPOINTS = {"files.save_settings", "files.trash_empty"}
# Endpoints that don't take a ?path / form path at all.
_NO_PATH_ENDPOINTS = {"files.trash", "files.trash_restore", "files.trash_delete", "files.clear_clipboard"}


@bp.before_request
def _enforce_file_site_scope():
    domains = _restricted_domains()
    if domains is None:
        return None
    cfg = current_app.config["PANEL_CONFIG"]

    def _deny():
        flash("You can only access your own website's files.", "error")
        # Redirect to the account's own assigned domain — never to
        # `files?path=` (empty), which is the sites root. With no site
        # assigned at all, bare `/files` shows browse()'s "no site" page.
        fallback = next(iter(sorted(domains)), None)
        if fallback is None:
            return redirect(f"{cfg.dashboard_url}files")
        return redirect(f"{cfg.dashboard_url}files?path={fallback}")

    endpoint = request.endpoint
    if endpoint in _RESTRICTED_BLOCKED_ENDPOINTS:
        return _deny()
    if endpoint in ("files.trash_restore", "files.trash_delete"):
        if not _trash_row_allowed(request.form.get("id", type=int), domains):
            return _deny()

    source = request.form if request.method == "POST" else request.args
    candidates = list(source.getlist("selected"))
    # Every path-taking endpoint defaults a missing path to "" (the sites
    # root), so a missing path is checked as "" too — except browsing the
    # root itself (bare "/files" or ?path=), which browse() narrows to this
    # account's own site folders. Nothing else may target the root.
    browsing_root = endpoint == "files.browse" and not source.get("path", "").strip().strip("/")
    if endpoint not in _NO_PATH_ENDPOINTS and not browsing_root:
        candidates.append(source.get("path", ""))
    # The clipboard is session-stored and set by an earlier /files/clipboard
    # request (itself already checked here) — but scope can change between
    # copying and pasting (a Super Admin could edit it mid-session), so
    # paste re-validates every clipboard entry too rather than trusting it.
    clipboard = session.get("file_clipboard")
    if clipboard:
        candidates.extend(clipboard.get("paths", []))
    for c in candidates:
        if not _path_allowed(c, domains):
            return _deny()

    # The site folder itself is the site's nginx document root — renaming,
    # deleting or cutting it would take the site down, so that's only for
    # an unrestricted admin. Everything inside it stays fully manageable.
    moving = endpoint in ("files.rename", "files.delete", "files.bulk_delete") or (
        endpoint == "files.set_clipboard" and source.get("mode") != "copy"
    )
    if moving:
        items = [source.get("path", "")] if endpoint in ("files.rename", "files.delete") else source.getlist("selected")
        root = system_ops.SITES_ROOT.resolve()
        if any(len(system_ops.safe_path(i).relative_to(root).parts) == 1 for i in items):
            flash("Your site's own top folder can't be renamed, moved or deleted.", "error")
            return redirect(f"{cfg.dashboard_url}files")
    return None


TEXT_EXTENSIONS = {
    ".html", ".htm", ".css", ".js", ".php", ".txt", ".json", ".xml", ".md", ".conf",
    ".ini", ".env", ".yml", ".yaml", ".log", ".sh", ".py", ".sql", ".htaccess",
    ".twig", ".tpl", ".vue", ".ts", ".jsx", ".tsx", ".csv", ".gitignore", ".editorconfig",
}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico"}
MAX_EDIT_SIZE = 2 * 1024 * 1024  # 2MB — anything bigger isn't a config/code file worth editing inline

# Where an archive goes after a successful unzip, instead of being deleted
# outright — a permanent delete of a multi-hundred-MB/GB upload on the back
# of one bad extraction is a real data-loss incident, not just an
# inconvenience, so this stays recoverable rather than gone forever.
UNZIPPED_TRASH_DIRNAME = ".unzipped-archives"

# Global Trash for deleted files/folders — a Delete moves the item here by
# default (tracked in the file_trash table so Restore knows where it came
# from) instead of removing it outright, on the same "don't make deletes
# irreversible by default" reasoning as UNZIPPED_TRASH_DIRNAME above.
# Skipping the Trash (permanent delete) is still available as an explicit
# opt-in, both per-item and in bulk.
FILE_TRASH_DIRNAME = ".file-trash"


def _trash_dir() -> Path:
    trash = system_ops.SITES_ROOT / FILE_TRASH_DIRNAME
    trash.mkdir(exist_ok=True)
    return trash


def _move_to_trash(db, target: Path) -> None:
    original_rel = str(target.relative_to(system_ops.SITES_ROOT))
    is_dir = target.is_dir()
    trash_name = f"{uuid.uuid4().hex}_{target.name}"
    shutil.move(str(target), str(_trash_dir() / trash_name))
    db.execute(
        "INSERT INTO file_trash (trash_name, original_rel_path, is_dir) VALUES (?, ?, ?)",
        (trash_name, original_rel, 1 if is_dir else 0),
    )
    db.commit()

ICON_MAP = {
    ".html": "filetype-html", ".htm": "filetype-html", ".css": "filetype-css",
    ".js": "filetype-js", ".php": "filetype-php", ".json": "filetype-json",
    ".xml": "filetype-xml", ".md": "filetype-md", ".txt": "file-earmark-text",
    ".zip": "file-earmark-zip", ".tar": "file-earmark-zip", ".gz": "file-earmark-zip",
    ".jpg": "file-earmark-image", ".jpeg": "file-earmark-image", ".png": "file-earmark-image",
    ".gif": "file-earmark-image", ".svg": "file-earmark-image", ".webp": "file-earmark-image",
    ".sql": "filetype-sql", ".py": "filetype-py", ".sh": "terminal", ".conf": "gear",
}


CM_MODE_MAP = {
    ".html": "htmlmixed", ".htm": "htmlmixed", ".css": "css", ".js": "javascript",
    ".json": "javascript", ".php": "php", ".xml": "xml", ".md": "markdown",
    ".conf": "text/plain", ".txt": "text/plain",
}


def _human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _icon_for(name: str, is_dir: bool) -> str:
    if is_dir:
        return "folder2"
    return ICON_MAP.get(Path(name).suffix.lower(), "file-earmark")


# Dotfiles like ".htaccess" or ".env" have no suffix under Path.suffix
# (pathlib treats a name starting with "." as having no extension at all),
# so they need to be matched on the full name too, not just the suffix.
NAMED_TEXT_FILES = {".htaccess", ".env", ".gitignore", ".editorconfig"}


def _is_editable(name: str, size: int) -> bool:
    if size > MAX_EDIT_SIZE:
        return False
    return name in NAMED_TEXT_FILES or Path(name).suffix.lower() in TEXT_EXTENSIONS


def _is_image(name: str) -> bool:
    return Path(name).suffix.lower() in IMAGE_EXTENSIONS


def _breadcrumbs(rel_path: str) -> list:
    if not rel_path:
        return []
    parts = rel_path.strip("/").split("/")
    crumbs = []
    built = []
    for part in parts:
        built.append(part)
        crumbs.append({"name": part, "rel_path": "/".join(built)})
    return crumbs


def _redirect_to(path: str):
    cfg = current_app.config["PANEL_CONFIG"]
    return redirect(f"{cfg.dashboard_url}files?path={path}")


# ---- File Manager settings (show-hidden / default directory) --------------
# Stored in the panel's own `settings` key/value table — same one the
# Terminal on/off toggle already uses. There's a single admin account, so
# these are simple global preferences, not per-user rows.
SETTING_SHOW_HIDDEN = "files_show_hidden"
SETTING_DEFAULT_PATH = "files_default_path"


def _get_setting(db, key: str, default: str) -> str:
    row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def _set_setting(db, key: str, value: str) -> None:
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    db.commit()


@bp.route("/files")
@login_required
def browse():
    cfg = current_app.config["PANEL_CONFIG"]
    show_hidden = _get_setting(g.db, SETTING_SHOW_HIDDEN, "0") == "1"

    # A bare "/files" with no ?path at all means "just navigated here" — use
    # the configured default directory. An explicit ?path=  (e.g. from
    # clicking the "root" breadcrumb) is a deliberate choice and must not be
    # overridden.
    if request.args.get("path") is None:
        domains = _restricted_domains()
        if domains is not None:
            # Site-restricted admin: land inside their own site's folder,
            # never the SITES_ROOT listing (which would show every domain
            # on the server, restricted or not).
            #
            # If `domains` is empty — the account's site_scope didn't
            # resolve to any real, still-existing site — fail CLOSED. The
            # old code fell back to `next(iter(sorted(domains)), "")`,
            # which for an empty set silently returns "", and "" resolves
            # to SITES_ROOT itself: the listing of every site on the
            # server. That's exactly the leak this account should never
            # be able to trigger, so it's refused outright instead of
            # falling through to a "default" path.
            if not domains:
                flash(
                    "Your account isn't assigned to any site yet — ask your Super Admin to check your "
                    "site restriction under Account.",
                    "error",
                )
                return render_template(
                    "files.html",
                    entries=[],
                    current_path="",
                    parent_path="",
                    breadcrumbs=[],
                    absolute_path="",
                    sites_root=str(system_ops.SITES_ROOT),
                    show_hidden=show_hidden,
                    default_path="",
                    trash_rel_path=None,
                    sites=[],
                    clipboard=None,
                    base_url=f"/{cfg.security_path}",
                    dashboard_url=f"/{cfg.security_path}/",
                    logout_url=f"/{cfg.security_path}/logout",
                )
            # One site: open it directly. Several: the root listing, which
            # below shows only this account's own site folders.
            rel_path = next(iter(domains)) if len(domains) == 1 else ""
        else:
            rel_path = _get_setting(g.db, SETTING_DEFAULT_PATH, "")
    else:
        rel_path = request.args.get("path", "")

    try:
        target = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}files?path=")

    if not target.exists():
        flash("Path not found.", "error")
        return redirect(f"{cfg.dashboard_url}files?path=")

    # A site-restricted admin's view of the sites root is only its own
    # site folders (the before_request hook lets exactly that listing
    # through, and nothing else at the root).
    restricted_domains = _restricted_domains()
    root_filter = restricted_domains if (
        restricted_domains is not None and target == system_ops.SITES_ROOT.resolve()
    ) else None

    entries = []
    if target.is_dir():
        for child in sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            if root_filter is not None and child.name not in root_filter:
                continue
            if child.name.startswith(".") and not show_hidden:
                continue
            stat = child.stat()
            entries.append({
                "name": child.name,
                "is_dir": child.is_dir(),
                "rel_path": str(child.relative_to(system_ops.SITES_ROOT)),
                "size": _human_size(stat.st_size) if child.is_file() else None,
                "editable": child.is_file() and _is_editable(child.name, stat.st_size),
                "viewable": child.is_file() and _is_image(child.name),
                "zippable": child.is_file() and child.suffix.lower() == ".zip",
                "icon": _icon_for(child.name, child.is_dir()),
                "mode": oct(stat.st_mode)[-3:],
                "type": "Folder" if child.is_dir() else (child.suffix[1:].upper() if child.suffix else "File"),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            })

    parent_rel = "" if target == system_ops.SITES_ROOT else str(
        target.parent.relative_to(system_ops.SITES_ROOT)
    )

    # Quick shortcut to this directory's own unzip-trash, if it has one —
    # saves hunting for it through Show Hidden Files.
    trash_candidate = target / UNZIPPED_TRASH_DIRNAME
    trash_rel_path = (
        str(trash_candidate.relative_to(system_ops.SITES_ROOT))
        if trash_candidate.is_dir() else None
    )

    # Restricted to the session's own assigned domain(s) — this list feeds
    # a "jump to site" dropdown in the template, which must never reveal
    # other tenants' domains to a site-restricted admin.
    restricted_domains = _restricted_domains()
    if restricted_domains is not None:
        sites = [{"domain": d} for d in sorted(restricted_domains)]
    else:
        sites = g.db.execute("SELECT domain FROM sites ORDER BY domain").fetchall()

    clipboard = session.get("file_clipboard")

    base = f"/{cfg.security_path}"
    return render_template(
        "files.html",
        entries=entries,
        current_path=rel_path,
        parent_path=parent_rel,
        breadcrumbs=_breadcrumbs(rel_path),
        absolute_path=str(target),
        sites_root=str(system_ops.SITES_ROOT),
        show_hidden=show_hidden,
        default_path=_get_setting(g.db, SETTING_DEFAULT_PATH, ""),
        trash_rel_path=trash_rel_path,
        sites=sites,
        clipboard=clipboard,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
    )


# ---- Clipboard: Copy / Cut / Paste -----------------------------------------
# Deliberately server-side (Flask session), not client-side JS state — the
# clipboard needs to survive navigating into a different folder before
# pasting, and every path in it must still go through safe_path() at paste
# time (never trust that a session-stored path is still valid/safe).
@bp.route("/files/clipboard", methods=["POST"])
@login_required
def set_clipboard():
    mode = request.form.get("mode", "").strip()
    selected = request.form.getlist("selected")

    if mode not in ("copy", "cut") or not selected:
        flash("Nothing selected to copy/cut.", "error")
        return _redirect_to(request.form.get("path", ""))

    # Validate every path now, not just at paste time, so a bad clipboard
    # entry is caught immediately with a clear error instead of silently
    # skipped later.
    for item_rel in selected:
        try:
            system_ops.safe_path(item_rel)
        except system_ops.SystemOpError as e:
            flash(str(e), "error")
            return _redirect_to(request.form.get("path", ""))

    session["file_clipboard"] = {"mode": mode, "paths": selected}
    flash(f"{len(selected)} item(s) {'copied' if mode == 'copy' else 'cut'}. Navigate to a folder and click Paste.", "success")
    return _redirect_to(request.form.get("path", ""))


@bp.route("/files/clipboard/clear", methods=["POST"])
@login_required
def clear_clipboard():
    session.pop("file_clipboard", None)
    return _redirect_to(request.form.get("path", ""))


@bp.route("/files/paste", methods=["POST"])
@login_required
def paste():
    rel_path = request.form.get("path", "")
    # Default behavior (unchecked) auto-renames a colliding item to
    # "name-copy1" so a plain Paste never destroys anything. "Paste &
    # Replace" is an explicit opt-in: any existing item with the same name
    # is moved to Trash (not deleted outright) and then replaced — this is
    # what someone re-deploying a folder like "admin"/"catalog"/"image"
    # over an existing site actually wants, without silently overwriting
    # by default.
    overwrite = request.form.get("overwrite") == "1"
    clipboard = session.get("file_clipboard")

    if not clipboard:
        flash("Clipboard is empty.", "error")
        return _redirect_to(rel_path)

    try:
        dest_dir = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return _redirect_to("")

    mode = clipboard["mode"]
    count = 0
    replaced = 0
    skipped = 0
    failed = 0
    for item_rel in clipboard["paths"]:
        try:
            source = system_ops.safe_path(item_rel)
        except system_ops.SystemOpError:
            continue
        if not source.exists():
            continue
        if source == dest_dir or dest_dir.is_relative_to(source):
            flash(f"Can't paste '{source.name}' into itself or its own subfolder — skipped.", "error")
            continue

        dest = dest_dir / source.name

        # Pasting an item back onto the exact path it already occupies (e.g.
        # copying a file, then pasting into the same folder with Replace
        # checked) is a no-op — there is nothing to trash or copy. Without
        # this guard, shutil.copy2()/copytree() would be called with
        # source == dest and raise SameFileError, which killed the whole
        # paste (including every other selected item in the same request).
        if dest == source:
            skipped += 1
            continue

        if dest.exists() and overwrite:
            _move_to_trash(g.db, dest)
            replaced += 1
        elif dest.exists():
            suffix = 1
            while dest.exists():
                dest = dest_dir / f"{source.stem}-copy{suffix}{source.suffix}" if source.is_file() \
                    else dest_dir / f"{source.name}-copy{suffix}"
                suffix += 1

        # Each item is copied/moved independently and a failure here is
        # reported and skipped rather than raising — one bad item (e.g. a
        # permissions error, a file that vanished mid-batch) no longer
        # aborts the whole paste and leaves the rest of a multi-select
        # silently un-pasted with a generic 500 page.
        try:
            if mode == "copy":
                if source.is_dir():
                    shutil.copytree(source, dest)
                else:
                    shutil.copy2(source, dest)
            else:  # cut
                shutil.move(str(source), str(dest))
        except (shutil.Error, OSError) as e:
            failed += 1
            flash(f"Couldn't paste '{source.name}': {e}", "error")
            continue

        system_ops.own_www_data(dest)
        count += 1

    if mode == "cut":
        session.pop("file_clipboard", None)

    parts = []
    if count:
        parts.append(f"Pasted {count} item(s)")
        if replaced:
            parts.append(f"replacing {replaced} existing item(s) (moved to Trash, recoverable)")
    if skipped:
        parts.append(f"{skipped} item(s) already in place — skipped")
    if parts:
        flash(", ".join(parts) + ".", "success")
    elif not failed:
        flash("Nothing to paste.", "error")
    return _redirect_to(rel_path)


@bp.route("/files/settings", methods=["POST"])
@login_required
def save_settings():
    cfg = current_app.config["PANEL_CONFIG"]
    show_hidden = "1" if request.form.get("show_hidden") == "on" else "0"
    default_path = request.form.get("default_path", "").strip().lstrip("/")

    # Validate it's a real, existing directory before saving — an invalid
    # saved default would otherwise send every future "/files" visit to a
    # "Path not found" error.
    if default_path:
        try:
            target = system_ops.safe_path(default_path)
        except system_ops.SystemOpError as e:
            flash(str(e), "error")
            return _redirect_to(request.form.get("path", ""))
        if not target.is_dir():
            flash("Default directory must be an existing folder.", "error")
            return _redirect_to(request.form.get("path", ""))

    _set_setting(g.db, SETTING_SHOW_HIDDEN, show_hidden)
    _set_setting(g.db, SETTING_DEFAULT_PATH, default_path)
    flash("File Manager settings saved.", "success")
    return _redirect_to(request.form.get("path", ""))


@bp.route("/files/edit")
@login_required
def edit():
    cfg = current_app.config["PANEL_CONFIG"]
    rel_path = request.args.get("path", "")

    try:
        target = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}files")

    if not target.is_file() or not _is_editable(target.name, target.stat().st_size):
        flash("This file type (or size) can't be edited here.", "error")
        return _redirect_to(str(target.parent.relative_to(system_ops.SITES_ROOT)))

    content = target.read_text(encoding="utf-8", errors="replace")
    base = f"/{cfg.security_path}"
    parent_path = str(target.parent.relative_to(system_ops.SITES_ROOT))
    return render_template(
        "file_edit.html",
        rel_path=rel_path,
        parent_path="" if parent_path == "." else parent_path,
        content=content,
        cm_mode=CM_MODE_MAP.get(target.suffix.lower(), "text/plain"),
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
    )


@bp.route("/files/save", methods=["POST"])
@login_required
def save():
    rel_path = request.form.get("path", "")
    content = request.form.get("content", "")

    try:
        target = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return _redirect_to("")

    if not target.is_file() or not _is_editable(target.name, target.stat().st_size):
        flash("This file type (or size) can't be edited here.", "error")
        return _redirect_to("")

    try:
        target.write_text(content, encoding="utf-8")
        system_ops.own_www_data(target)
        flash(f"Saved {target.name}.", "success")
    except PermissionError:
        flash(f"Can't save {target.name} — it's protected by Tamper-proofing. Disable that first to edit it.", "error")
    return _redirect_to(str(target.parent.relative_to(system_ops.SITES_ROOT)))


@bp.route("/files/view")
@login_required
def view():
    cfg = current_app.config["PANEL_CONFIG"]
    rel_path = request.args.get("path", "")

    try:
        target = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}files")

    if not target.is_file():
        flash("Not a file.", "error")
        return redirect(f"{cfg.dashboard_url}files")

    # Served inline (no as_attachment) so the browser renders it directly —
    # download() deliberately forces a save-to-disk prompt instead, which is
    # the wrong behavior for "just let me look at this image".
    return send_file(target)


@bp.route("/files/upload", methods=["POST"])
@login_required
def upload():
    rel_path = request.form.get("path", "")
    uploaded = request.files.get("file")

    try:
        target_dir = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return _redirect_to("")

    if not uploaded or not uploaded.filename:
        flash("No file selected.", "error")
        return _redirect_to(rel_path)

    # Filename comes from the client — never trust it as a path component.
    # Path.name strips any directory parts, so "../../evil" becomes "evil".
    safe_name = Path(uploaded.filename).name
    if not safe_name:
        flash("Invalid filename.", "error")
        return _redirect_to(rel_path)

    dest = target_dir / safe_name
    uploaded.save(dest)
    system_ops.own_www_data(dest)
    flash(f"Uploaded {safe_name}.", "success")
    return _redirect_to(rel_path)


@bp.route("/files/delete", methods=["POST"])
@login_required
def delete():
    rel_path = request.form.get("path", "")
    permanent = request.form.get("permanent") == "on"

    try:
        target = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return _redirect_to("")

    if target == system_ops.SITES_ROOT:
        flash("Can't delete the sites root.", "error")
        return _redirect_to("")

    parent_rel = str(target.parent.relative_to(system_ops.SITES_ROOT))
    name = target.name

    try:
        if permanent:
            if target.is_dir():
                shutil.rmtree(target)
            elif target.is_file():
                target.unlink()
            flash(f"Permanently deleted {name}.", "success")
        else:
            _move_to_trash(g.db, target)
            flash(f"Moved {name} to Trash.", "success")
    except PermissionError:
        flash(f"Can't delete {name} — it's protected by Tamper-proofing. Disable that first.", "error")

    return _redirect_to(parent_rel)


@bp.route("/files/mkdir", methods=["POST"])
@login_required
def mkdir():
    rel_path = request.form.get("path", "")
    name = request.form.get("name", "").strip()

    try:
        parent = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return _redirect_to("")

    safe_name = Path(name).name  # strip any path components, same rule as upload
    if not safe_name:
        flash("Invalid folder name.", "error")
        return _redirect_to(rel_path)

    new_dir = parent / safe_name
    new_dir.mkdir(exist_ok=True)
    system_ops.own_www_data(new_dir)
    flash(f"Created folder {safe_name}.", "success")
    return _redirect_to(rel_path)


@bp.route("/files/download")
@login_required
def download():
    cfg = current_app.config["PANEL_CONFIG"]
    rel_path = request.args.get("path", "")

    try:
        target = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}files")

    if not target.is_file():
        flash("Not a file.", "error")
        return redirect(f"{cfg.dashboard_url}files")

    return send_file(target, as_attachment=True, download_name=target.name)


@bp.route("/files/rename", methods=["POST"])
@login_required
def rename():
    rel_path = request.form.get("path", "")
    new_name = Path(request.form.get("new_name", "")).name  # strip any path components

    try:
        target = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return _redirect_to("")

    if not new_name:
        flash("Invalid new name.", "error")
        return _redirect_to(str(target.parent.relative_to(system_ops.SITES_ROOT)))

    if not target.exists():
        flash("Item not found.", "error")
        return _redirect_to("")

    destination = target.parent / new_name
    if destination.exists():
        flash(f"'{new_name}' already exists.", "error")
        return _redirect_to(str(target.parent.relative_to(system_ops.SITES_ROOT)))

    try:
        target.rename(destination)
        system_ops.own_www_data(destination)
        flash(f"Renamed to {new_name}.", "success")
    except PermissionError:
        flash(f"Can't rename {target.name} — it's protected by Tamper-proofing. Disable that first.", "error")
    return _redirect_to(str(target.parent.relative_to(system_ops.SITES_ROOT)))


@bp.route("/files/mkfile", methods=["POST"])
@login_required
def mkfile():
    rel_path = request.form.get("path", "")
    name = Path(request.form.get("name", "").strip()).name

    try:
        parent = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return _redirect_to("")

    if not name:
        flash("Invalid file name.", "error")
        return _redirect_to(rel_path)

    target = parent / name
    if target.exists():
        flash(f"'{name}' already exists.", "error")
        return _redirect_to(rel_path)

    target.touch()
    system_ops.own_www_data(target)
    flash(f"Created {name}.", "success")
    return _redirect_to(rel_path)


@bp.route("/files/chmod", methods=["POST"])
@login_required
def chmod():
    rel_path = request.form.get("path", "")
    mode_str = request.form.get("mode", "").strip()

    try:
        target = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return _redirect_to("")

    if not (mode_str.isdigit() and len(mode_str) == 3 and all(c in "01234567" for c in mode_str)):
        flash("Permissions must be 3 octal digits, e.g. 755.", "error")
        return _redirect_to(str(target.parent.relative_to(system_ops.SITES_ROOT)))

    try:
        target.chmod(int(mode_str, 8))
        flash(f"Permissions set to {mode_str}.", "success")
    except PermissionError:
        flash(f"Can't change permissions on {target.name} — it's protected by Tamper-proofing. Disable that first.", "error")
    return _redirect_to(str(target.parent.relative_to(system_ops.SITES_ROOT)))


@bp.route("/files/bulk-delete", methods=["POST"])
@login_required
def bulk_delete():
    rel_path = request.form.get("path", "")
    permanent = request.form.get("permanent") == "on"
    selected = request.form.getlist("selected")
    count = 0
    blocked = 0

    for item_rel in selected:
        try:
            target = system_ops.safe_path(item_rel)
        except system_ops.SystemOpError:
            continue
        if target == system_ops.SITES_ROOT:
            continue
        if not target.exists():
            continue
        try:
            if permanent:
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            else:
                _move_to_trash(g.db, target)
            count += 1
        except PermissionError:
            blocked += 1

    flash(f"{'Permanently deleted' if permanent else 'Moved to Trash'}: {count} item(s).", "success")
    if blocked:
        flash(f"{blocked} item(s) skipped — protected by Tamper-proofing. Disable that first to delete them.", "error")
    return _redirect_to(rel_path)


@bp.route("/files/zip", methods=["POST"])
@login_required
def zip_selected():
    rel_path = request.form.get("path", "")
    selected = request.form.getlist("selected")

    try:
        target_dir = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return _redirect_to("")

    if not selected:
        flash("Nothing selected to zip.", "error")
        return _redirect_to(rel_path)

    archive_name = "archive.zip"
    suffix = 1
    while (target_dir / archive_name).exists():
        archive_name = f"archive-{suffix}.zip"
        suffix += 1
    archive_path = target_dir / archive_name

    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for item_rel in selected:
            try:
                item = system_ops.safe_path(item_rel)
            except system_ops.SystemOpError:
                continue
            if item.is_file():
                zf.write(item, arcname=item.name)
            elif item.is_dir():
                for sub in item.rglob("*"):
                    if sub.is_file():
                        zf.write(sub, arcname=str(Path(item.name) / sub.relative_to(item)))

    system_ops.own_www_data(archive_path)
    flash(f"Created {archive_name}.", "success")
    return _redirect_to(rel_path)


@bp.route("/files/unzip", methods=["POST"])
@login_required
def unzip():
    rel_path = request.form.get("path", "")

    try:
        target = system_ops.safe_path(rel_path)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return _redirect_to("")

    if not target.is_file() or target.suffix.lower() != ".zip":
        flash("Not a .zip file.", "error")
        return _redirect_to(str(target.parent.relative_to(system_ops.SITES_ROOT)))

    extract_dir = target.parent

    try:
        with zipfile.ZipFile(target) as zf:
            members = zf.namelist()
            if not members:
                flash("Archive is empty — nothing to extract. The zip was left untouched.", "error")
                return _redirect_to(str(extract_dir.relative_to(system_ops.SITES_ROOT)))
            for member in members:
                # "Zip slip" protection: every extracted path must resolve
                # inside extract_dir, even though safe_path() already
                # constrains the ZIP FILE itself — a malicious member name
                # like "../../etc/passwd" inside the archive is a completely
                # separate attack surface from the path the browser sent.
                member_path = (extract_dir / member).resolve()
                if not str(member_path).startswith(str(extract_dir.resolve())):
                    flash(f"Refused to extract unsafe path in archive: {member!r}. The zip was left untouched.", "error")
                    return _redirect_to(str(extract_dir.relative_to(system_ops.SITES_ROOT)))
            # Extracted member-by-member rather than one zf.extractall()
            # call: a zip built on Windows with a non-UTF-8 filename (common
            # with non-ASCII names — Bengali, Arabic, etc.) doesn't set the
            # UTF-8 flag bit, so Python decodes it as cp437 by default and
            # produces mangled garbage that can exceed Linux's 255-byte
            # filename limit. extractall() dies on the very first such
            # entry and takes the WHOLE archive down with it; extracting
            # one at a time means one bad filename just gets skipped
            # (after trying the standard cp437-mis-decode recovery) while
            # everything else in a large real-world archive still comes
            # through.
            skipped = []
            replaced = 0
            for member in members:
                name_to_extract = member
                info = zf.getinfo(member)
                if not (info.flag_bits & 0x800):  # UTF-8 flag not set
                    try:
                        name_to_extract = member.encode("cp437").decode("utf-8")
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        pass  # fall back to the name Python already gave us

                # Unlike Paste & Replace, extract() has no built-in protection
                # against clobbering an existing file — a zip that happens to
                # share paths with the destination (e.g. a theme patch's
                # system/library/... landing on top of a live site's own
                # system/library/...) would silently overwrite it with zero
                # way back. Trash the pre-existing FILE (never a directory —
                # zip members are files; their parent dirs are untouched,
                # which is exactly what makes this a merge, not a wholesale
                # folder swap) before extracting over it.
                dest_path = extract_dir / name_to_extract
                if dest_path.is_file():
                    try:
                        _move_to_trash(g.db, dest_path)
                        replaced += 1
                    except OSError:
                        pass

                try:
                    if name_to_extract != member:
                        info.filename = name_to_extract
                    zf.extract(info, extract_dir)
                except OSError:
                    skipped.append(member)

            top_level_names = {Path(m).parts[0] for m in members if m not in skipped}
            for name in top_level_names:
                system_ops.own_www_data(extract_dir / name)

            if skipped:
                flash(
                    f"Extracted with {len(skipped)} file(s) skipped due to invalid/corrupted names in the archive "
                    f"(first: {skipped[0]!r}). Everything else extracted normally.",
                    "error",
                )
            if replaced:
                flash(
                    f"{replaced} existing file(s) were overwritten by this extraction — "
                    f"the previous versions were moved to Trash and can be restored from there.",
                    "success",
                )
    except zipfile.BadZipFile:
        flash("Invalid or corrupted zip file. The zip was left untouched.", "error")
        return _redirect_to(str(extract_dir.relative_to(system_ops.SITES_ROOT)))

    # Verify something actually landed on disk before touching the source
    # archive at all — a past incident here deleted a large upload outright
    # with zero files extracted for reasons that were never pinned down, so
    # this check is deliberately paranoid rather than trusting extractall()
    # not raising an exception as proof it worked. Checks every top-level
    # name, not just the first member — that specific one may be exactly
    # the one that got skipped above.
    if not any((extract_dir / name).exists() for name in top_level_names):
        flash(
            f"Extraction reported success but no files appeared on disk — "
            f"the zip was left untouched as a precaution. Please report this.",
            "error",
        )
        return _redirect_to(str(extract_dir.relative_to(system_ops.SITES_ROOT)))

    # Archive is moved into a hidden, recoverable folder rather than
    # deleted outright — decluttering the visible file list without risking
    # permanent loss of a large upload if something goes wrong again.
    trash_dir = extract_dir / UNZIPPED_TRASH_DIRNAME
    trash_dir.mkdir(exist_ok=True)
    trash_target = trash_dir / target.name
    suffix = 1
    while trash_target.exists():
        trash_target = trash_dir / f"{target.stem}-{suffix}{target.suffix}"
        suffix += 1
    shutil.move(str(target), str(trash_target))
    system_ops.own_www_data(trash_dir)

    flash(
        f"Extracted {target.name}. The original archive was moved to "
        f"{UNZIPPED_TRASH_DIRNAME}/ (hidden) instead of being deleted, in case you need it again.",
        "success",
    )
    return _redirect_to(str(extract_dir.relative_to(system_ops.SITES_ROOT)))


# ---- Trash: everything deleted via /files/delete or /files/bulk-delete
# (unless "permanent" was checked) lands here, tracked in file_trash so it
# can be restored to its original location. ----------------------------------
@bp.route("/files/trash")
@login_required
def trash():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    rows = g.db.execute("SELECT * FROM file_trash ORDER BY deleted_at DESC").fetchall()
    domains = _restricted_domains()
    if domains is not None:
        # Trash is shared by every site — show only this account's own.
        rows = [r for r in rows if _path_allowed(r["original_rel_path"], domains)]

    items = []
    total_size = 0
    for row in rows:
        item_path = _trash_dir() / row["trash_name"]
        size = 0
        if item_path.is_file():
            size = item_path.stat().st_size
        elif item_path.is_dir():
            size = sum(f.stat().st_size for f in item_path.rglob("*") if f.is_file())
        total_size += size
        items.append({
            "id": row["id"],
            "name": Path(row["original_rel_path"]).name,
            "original_rel_path": row["original_rel_path"],
            "is_dir": bool(row["is_dir"]),
            "deleted_at": row["deleted_at"],
            "size": _human_size(size),
            "exists": item_path.exists(),
        })

    return render_template(
        "files_trash.html",
        items=items,
        total_size=_human_size(total_size),
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
    )


@bp.route("/files/trash/restore", methods=["POST"])
@login_required
def trash_restore():
    cfg = current_app.config["PANEL_CONFIG"]
    item_id = request.form.get("id", type=int)
    row = g.db.execute("SELECT * FROM file_trash WHERE id = ?", (item_id,)).fetchone()

    if not row:
        flash("Trash item not found.", "error")
        return redirect(f"{cfg.dashboard_url}files/trash")

    trash_path = _trash_dir() / row["trash_name"]
    if not trash_path.exists():
        g.db.execute("DELETE FROM file_trash WHERE id = ?", (item_id,))
        g.db.commit()
        flash("That item is missing from Trash storage — removed from the list.", "error")
        return redirect(f"{cfg.dashboard_url}files/trash")

    try:
        restore_path = system_ops.safe_path(row["original_rel_path"])
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}files/trash")

    if restore_path.exists():
        flash(f"Can't restore — {row['original_rel_path']} already exists there.", "error")
        return redirect(f"{cfg.dashboard_url}files/trash")

    restore_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(trash_path), str(restore_path))
    system_ops.own_www_data(restore_path)
    g.db.execute("DELETE FROM file_trash WHERE id = ?", (item_id,))
    g.db.commit()

    flash(f"Restored {row['original_rel_path']}.", "success")
    return redirect(f"{cfg.dashboard_url}files/trash")


@bp.route("/files/trash/delete", methods=["POST"])
@login_required
def trash_delete():
    cfg = current_app.config["PANEL_CONFIG"]
    item_id = request.form.get("id", type=int)
    row = g.db.execute("SELECT * FROM file_trash WHERE id = ?", (item_id,)).fetchone()

    if row:
        trash_path = _trash_dir() / row["trash_name"]
        if trash_path.is_dir():
            shutil.rmtree(trash_path, ignore_errors=True)
        elif trash_path.is_file():
            trash_path.unlink(missing_ok=True)
        g.db.execute("DELETE FROM file_trash WHERE id = ?", (item_id,))
        g.db.commit()
        flash(f"Permanently deleted {Path(row['original_rel_path']).name}.", "success")

    return redirect(f"{cfg.dashboard_url}files/trash")


@bp.route("/files/trash/empty", methods=["POST"])
@login_required
def trash_empty():
    cfg = current_app.config["PANEL_CONFIG"]
    shutil.rmtree(_trash_dir(), ignore_errors=True)
    count = g.db.execute("SELECT COUNT(*) AS n FROM file_trash").fetchone()["n"]
    g.db.execute("DELETE FROM file_trash")
    g.db.commit()
    flash(f"Trash emptied — {count} item(s) permanently deleted.", "success")
    return redirect(f"{cfg.dashboard_url}files/trash")
