"""Dropshipping — source products from 1688/AliExpress/Taobao (via
whichever API/aggregator account the admin brings) and import them
directly into one of this panel's hosted OpenCart sites. Order fulfillment
(scripts/run_fulfillment.py) then watches that site's orders and attempts
to place the matching purchase on the source platform automatically.

The actual API calls live in sourcing_providers.py, deliberately built as
a generic adapter rather than a verified integration — see that module's
docstring. This blueprint is routes + the OpenCart-DB import step only.
"""
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session

from . import opencart_db, sourcing_providers
from .security import login_required

bp = Blueprint("dropshipping", __name__)

PLATFORMS = {"1688": "1688.com", "aliexpress": "AliExpress", "taobao": "Taobao"}


def _get_provider(db, platform: str):
    row = db.execute("SELECT * FROM sourcing_providers WHERE platform = ?", (platform,)).fetchone()
    return dict(row) if row else None


@bp.route("/dropshipping")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    providers = {p: _get_provider(g.db, p) for p in PLATFORMS}
    linked_sites = g.db.execute(
        "SELECT ds.*, s.domain FROM dropship_sites ds JOIN sites s ON s.id = ds.site_id ORDER BY s.domain"
    ).fetchall()
    recent = g.db.execute(
        "SELECT sp.*, s.domain FROM sourced_products sp JOIN sites s ON s.id = sp.site_id "
        "ORDER BY sp.imported_at DESC LIMIT 20"
    ).fetchall()
    sites = g.db.execute("SELECT * FROM sites WHERE site_type = 'php' ORDER BY domain").fetchall()
    databases = g.db.execute("SELECT * FROM databases ORDER BY db_name").fetchall()

    return render_template(
        "dropshipping.html",
        platforms=PLATFORMS,
        providers=providers,
        linked_sites=linked_sites,
        recent=recent,
        sites=sites,
        databases=databases,
        search_results=session.pop("dropship_search_results", None),
        search_platform=session.pop("dropship_search_platform", None),
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/dropshipping/providers", methods=["POST"])
@login_required
def save_provider():
    cfg = current_app.config["PANEL_CONFIG"]
    platform = request.form.get("platform", "").strip()
    if platform not in PLATFORMS:
        flash("Unknown platform.", "error")
        return redirect(f"{cfg.dashboard_url}dropshipping")

    api_base_url = request.form.get("api_base_url", "").strip()
    app_key = request.form.get("app_key", "").strip()
    app_secret = request.form.get("app_secret", "").strip()
    enabled = 1 if request.form.get("enabled") == "on" else 0

    g.db.execute(
        "INSERT INTO sourcing_providers (platform, api_base_url, app_key, app_secret, enabled) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(platform) DO UPDATE SET api_base_url=excluded.api_base_url, app_key=excluded.app_key, "
        "app_secret=excluded.app_secret, enabled=excluded.enabled",
        (platform, api_base_url, app_key, app_secret, enabled),
    )
    g.db.commit()
    flash(f"{PLATFORMS[platform]} provider settings saved.", "success")
    return redirect(f"{cfg.dashboard_url}dropshipping")


@bp.route("/dropshipping/connect-site", methods=["POST"])
@login_required
def connect_site():
    cfg = current_app.config["PANEL_CONFIG"]
    site_id = request.form.get("site_id", type=int)
    db_name = request.form.get("db_name", "").strip()

    if not site_id or not db_name:
        flash("Choose both a site and a database.", "error")
        return redirect(f"{cfg.dashboard_url}dropshipping")

    g.db.execute("INSERT INTO dropship_sites (site_id, db_name) VALUES (?, ?)", (site_id, db_name))
    g.db.commit()
    flash("Site connected for dropshipping.", "success")
    return redirect(f"{cfg.dashboard_url}dropshipping")


@bp.route("/dropshipping/disconnect-site", methods=["POST"])
@login_required
def disconnect_site():
    cfg = current_app.config["PANEL_CONFIG"]
    link_id = request.form.get("id", type=int)
    g.db.execute("DELETE FROM dropship_sites WHERE id = ?", (link_id,))
    g.db.commit()
    flash("Site disconnected.", "success")
    return redirect(f"{cfg.dashboard_url}dropshipping")


@bp.route("/dropshipping/search", methods=["POST"])
@login_required
def search():
    cfg = current_app.config["PANEL_CONFIG"]
    platform = request.form.get("platform", "").strip()
    keyword = request.form.get("keyword", "").strip()

    if platform not in PLATFORMS or not keyword:
        flash("Choose a platform and enter a search keyword.", "error")
        return redirect(f"{cfg.dashboard_url}dropshipping")

    provider = _get_provider(g.db, platform)
    try:
        results = sourcing_providers.search_products(provider, keyword)
    except sourcing_providers.SourcingError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}dropshipping")

    session["dropship_search_results"] = results
    session["dropship_search_platform"] = platform
    flash(f"Found {len(results)} result(s) for {keyword!r} on {PLATFORMS[platform]}.", "success")
    return redirect(f"{cfg.dashboard_url}dropshipping")


@bp.route("/dropshipping/import", methods=["POST"])
@login_required
def import_product():
    cfg = current_app.config["PANEL_CONFIG"]
    platform = request.form.get("platform", "").strip()
    product_id = request.form.get("product_id", "").strip()
    title = request.form.get("title", "").strip()
    price = request.form.get("price", type=float) or 0.0
    source_url = request.form.get("source_url", "").strip()
    link_id = request.form.get("link_id", type=int)

    link = g.db.execute("SELECT * FROM dropship_sites WHERE id = ?", (link_id,)).fetchone()
    if not link:
        flash("Choose which connected site to import into.", "error")
        return redirect(f"{cfg.dashboard_url}dropshipping")

    model = f"{platform}-{product_id}"[:64]
    try:
        opencart_product_id = opencart_db.insert_product(
            link["db_name"], title, f"Imported from {PLATFORMS.get(platform, platform)}: {source_url}", price, model
        )
    except opencart_db.OpenCartDbError as e:
        flash(f"Import failed: {e}", "error")
        return redirect(f"{cfg.dashboard_url}dropshipping")

    g.db.execute(
        "INSERT INTO sourced_products (site_id, platform, source_product_id, source_url, opencart_product_id, title, price) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (link["site_id"], platform, product_id, source_url, opencart_product_id, title, price),
    )
    g.db.commit()
    flash(f"Imported {title!r} as product #{opencart_product_id}.", "success")
    return redirect(f"{cfg.dashboard_url}dropshipping")


@bp.route("/dropshipping/orders")
@login_required
def orders():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    rows = g.db.execute(
        "SELECT fo.*, sp.title, s.domain FROM fulfillment_orders fo "
        "JOIN sourced_products sp ON sp.id = fo.sourced_product_id "
        "JOIN sites s ON s.id = fo.site_id "
        "ORDER BY fo.created_at DESC"
    ).fetchall()

    return render_template(
        "dropshipping_orders.html",
        orders=rows,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/dropshipping/orders/<int:order_id>/retry", methods=["POST"])
@login_required
def retry_order(order_id):
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM fulfillment_orders WHERE id = ?", (order_id,)).fetchone()
    if not row:
        flash("Fulfillment order not found.", "error")
        return redirect(f"{cfg.dashboard_url}dropshipping/orders")

    provider = _get_provider(g.db, row["platform"])
    sourced = g.db.execute("SELECT * FROM sourced_products WHERE id = ?", (row["sourced_product_id"],)).fetchone()
    try:
        result = sourcing_providers.place_order(provider, sourced["source_product_id"], 1, {"detail": row["detail"]})
        g.db.execute(
            "UPDATE fulfillment_orders SET status = ?, source_order_id = ?, updated_at = datetime('now') WHERE id = ?",
            (result["status"], result["order_id"], order_id),
        )
        g.db.commit()
        flash("Fulfillment order placed.", "success")
    except sourcing_providers.SourcingError as e:
        g.db.execute(
            "UPDATE fulfillment_orders SET status = 'failed', detail = ?, updated_at = datetime('now') WHERE id = ?",
            (str(e), order_id),
        )
        g.db.commit()
        flash(f"Retry failed: {e}", "error")

    return redirect(f"{cfg.dashboard_url}dropshipping/orders")
