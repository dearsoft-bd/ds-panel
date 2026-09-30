"""Web Terminal — off by default, the single highest-risk feature in this
codebase (a real root shell reachable over the network). Three independent
gates must all pass before a single byte of shell I/O happens:

  1. A valid authenticated session (login_required on the HTTP page, and
     the same session check repeated inside the websocket handler itself —
     the WS upgrade request is a separate connection and must not inherit
     trust from anywhere else).
  2. The admin has explicitly flipped "Enable Terminal" on for this
     install (stored in the panel's own settings table, default OFF).
     Enabling it does NOT persist across reads by accident — it's a
     deliberate row write the admin makes from an authenticated session.
  3. The WebSocket's Origin header must match this server's own host —
     without this, any other website the admin has open in another tab
     could silently open a WS connection using the admin's existing
     session cookie and get a live shell (a real, well-known class of
     WebSocket CSRF).

No new dependency for the PTY bridge itself — just the stdlib `pty` module
wrapping a real `/bin/bash`, piped to the browser via flask-sock.
"""
import errno
import fcntl
import os
import pty
import select
import struct
import termios

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session

from .security import login_required

bp = Blueprint("terminal", __name__)

SETTING_KEY = "terminal_enabled"


def is_terminal_enabled(db) -> bool:
    row = db.execute("SELECT value FROM settings WHERE key = ?", (SETTING_KEY,)).fetchone()
    return bool(row and row["value"] == "1")


@bp.route("/terminal")
@login_required
def page():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    return render_template(
        "terminal.html",
        enabled=is_terminal_enabled(g.db),
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        ws_url=f"wss://{request.host}{base}/terminal/ws",
    )


@bp.route("/terminal/toggle", methods=["POST"])
@login_required
def toggle():
    cfg = current_app.config["PANEL_CONFIG"]
    turn_on = request.form.get("enable") == "1"
    g.db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (SETTING_KEY, "1" if turn_on else "0"),
    )
    g.db.commit()
    flash("Terminal enabled." if turn_on else "Terminal disabled.", "success")
    return redirect(f"/{cfg.security_path}/terminal")


def _origin_is_trusted(origin: str, host: str) -> bool:
    if not origin:
        return False
    # origin looks like "https://host:port" — compare just the host[:port] part.
    stripped = origin.split("//", 1)[-1]
    return stripped == host


def register_terminal_ws(app, sock, security_path: str, get_db):
    """Registers the actual WS route directly on the app (not the
    blueprint) — flask-sock's blueprint support varies by version, and this
    is the one route where being 100% certain of exactly what's registered
    matters more than tidiness.
    """
    from .db import get_connection  # local import to avoid a cycle

    @sock.route(f"/{security_path}/terminal/ws")
    def terminal_ws(ws):
        if not session.get("user_id"):
            ws.close()
            return

        # This route is registered on the app, not the "terminal" blueprint,
        # so the role hooks in app/__init__.py never map it to the
        # "terminal" feature — and a WS handshake is a GET, which the viewer
        # hook always lets through. Without this check a viewer, a custom
        # role without Terminal, or a site-restricted admin could open a
        # root shell by connecting straight to this URL.
        role = session.get("role")
        permissions = set((session.get("permissions") or "").split(","))
        if not (
            role == "super_admin"
            or (role == "admin" and not session.get("site_scope"))
            or (role == "custom" and "terminal" in permissions)
        ):
            ws.close()
            return

        origin = request.headers.get("Origin", "")
        if not _origin_is_trusted(origin, request.host):
            ws.close()
            return

        db = get_connection(current_app.config["PANEL_CONFIG"].db_path)
        try:
            if not is_terminal_enabled(db):
                ws.close()
                return
        finally:
            db.close()

        pid, fd = pty.fork()
        if pid == 0:
            os.environ["TERM"] = "xterm-256color"
            os.execvp("/bin/bash", ["/bin/bash"])
            os._exit(1)

        try:
            _bridge(ws, fd)
        finally:
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
            os.close(fd)


def _bridge(ws, fd):
    """Shuttle bytes both directions between the websocket and the PTY
    until either side closes. flask-sock's ws.receive() blocks, so this
    runs the PTY-read side via select() on a short timeout and interleaves
    a non-blocking check for incoming websocket data.
    """
    import threading

    def pty_to_ws():
        while True:
            try:
                ready, _, _ = select.select([fd], [], [], 0.1)
                if ready:
                    data = os.read(fd, 4096)
                    if not data:
                        break
                    ws.send(data.decode(errors="replace"))
            except OSError as e:
                # EIO: shell exited, PTY slave closed. EBADF: the main
                # thread already closed fd during cleanup (a normal race
                # at disconnect time, not a real error — select() can wake
                # up on a soon-to-be-closed fd right as the other thread
                # gets there first). Both mean "stop reading", not "crash".
                if e.errno in (errno.EIO, errno.EBADF):
                    break
                raise
            except Exception:
                break

    reader = threading.Thread(target=pty_to_ws, daemon=True)
    reader.start()

    while True:
        message = ws.receive()
        if message is None:
            break
        if isinstance(message, str) and message.startswith("\x01RESIZE:"):
            try:
                cols, rows = message[8:].split(",")
                _resize_pty(fd, int(rows), int(cols))
            except (ValueError, OSError):
                pass
            continue
        try:
            os.write(fd, message.encode() if isinstance(message, str) else message)
        except OSError:
            break

    reader.join(timeout=1)


def _resize_pty(fd, rows: int, cols: int) -> None:
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
