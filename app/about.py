"""About Us — static info page: who built DS Panel, the owner, and how to
get in touch. Never gated by role/permissions (like Dashboard/Monitor) —
every logged-in user, whatever their role, can see who made the panel
they're using and how to reach support.
"""
from flask import Blueprint, current_app, render_template, session

from .security import login_required

bp = Blueprint("about", __name__)


@bp.route("/about")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    return render_template(
        "about.html",
        base_url=f"/{cfg.security_path}",
        dashboard_url=f"/{cfg.security_path}/",
        logout_url=f"/{cfg.security_path}/logout",
        username=session.get("username"),
    )
