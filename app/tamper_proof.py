"""Website Tamper-proof — locks a site's files against modification using
the filesystem's immutable attribute (chattr +i), recursively, excluding
paths a site normally needs to keep writing to (uploads/cache/storage/etc).
See system_ops.py's own section docstring for the exclusion list and why
this mechanism was chosen (same one aaPanel's equivalent feature uses).
"""
from pathlib import Path

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session

from . import system_ops
from .security import login_required

bp = Blueprint("tamper_proof", __name__)


@bp.route("/tamper-proof")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    sites = g.db.execute("SELECT * FROM sites WHERE site_type = 'php' ORDER BY domain").fetchall()

    status = {s["id"]: system_ops.is_tamper_proof_enabled(Path(s["document_root"])) for s in sites}

    return render_template(
        "tamper_proof.html",
        sites=sites,
        status=status,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/tamper-proof/toggle", methods=["POST"])
@login_required
def toggle():
    cfg = current_app.config["PANEL_CONFIG"]
    site_id = request.form.get("site_id", type=int)
    enable = request.form.get("enabled") == "on"

    row = g.db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not row:
        flash("Site not found.", "error")
        return redirect(f"{cfg.dashboard_url}tamper-proof")

    try:
        system_ops.set_tamper_proof_enabled(Path(row["document_root"]), enable)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}tamper-proof")

    flash(f"Tamper-proofing {'enabled' if enable else 'disabled'} for {row['domain']}.", "success")
    return redirect(f"{cfg.dashboard_url}tamper-proof")
