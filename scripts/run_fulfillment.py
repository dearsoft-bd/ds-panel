#!/usr/bin/env python3
"""Runs periodically via cron (see install.sh). For every site connected
under Dropshipping, scans its OpenCart orders for ones containing a
sourced product, and — for any not already tracked — records a
fulfillment_orders row and attempts to place the matching purchase on the
source platform via sourcing_providers.place_order().

Standalone script, not a Flask route, same reasoning as
run_backup_jobs.py: this shouldn't depend on the web process being up.
"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import opencart_db, sourcing_providers  # noqa: E402

DB_PATH = Path("/etc/ds-panel/panel.db")


def _get_provider(conn: sqlite3.Connection, platform: str):
    row = conn.execute("SELECT * FROM sourcing_providers WHERE platform = ?", (platform,)).fetchone()
    return dict(row) if row else None


def process_site(conn: sqlite3.Connection, link: sqlite3.Row) -> None:
    products = conn.execute(
        "SELECT id, platform, source_product_id, opencart_product_id FROM sourced_products "
        "WHERE site_id = ? AND opencart_product_id IS NOT NULL",
        (link["site_id"],),
    ).fetchall()
    if not products:
        return
    by_oc_id = {p["opencart_product_id"]: p for p in products}

    try:
        order_rows = opencart_db.fetch_new_orders(link["db_name"], list(by_oc_id.keys()))
    except opencart_db.OpenCartDbError as e:
        print(f"[FAIL] {link['db_name']}: {e}", file=sys.stderr)
        return

    for row in order_rows:
        sourced = by_oc_id.get(row["product_id"])
        if not sourced:
            continue

        existing = conn.execute(
            "SELECT id FROM fulfillment_orders WHERE site_id = ? AND opencart_order_id = ? AND sourced_product_id = ?",
            (link["site_id"], row["order_id"], sourced["id"]),
        ).fetchone()
        if existing:
            continue

        cur = conn.execute(
            "INSERT INTO fulfillment_orders (site_id, opencart_order_id, sourced_product_id, platform, status) "
            "VALUES (?, ?, ?, ?, 'pending')",
            (link["site_id"], row["order_id"], sourced["id"], sourced["platform"]),
        )
        fulfillment_id = cur.lastrowid
        conn.commit()

        provider = _get_provider(conn, sourced["platform"])
        address = {
            "address_1": row["shipping_address_1"],
            "address_2": row["shipping_address_2"],
            "city": row["shipping_city"],
            "postcode": row["shipping_postcode"],
            "country": row["shipping_country"],
            "phone": row["telephone"],
        }
        try:
            result = sourcing_providers.place_order(provider, sourced["source_product_id"], row["quantity"], address)
            conn.execute(
                "UPDATE fulfillment_orders SET status = ?, source_order_id = ?, updated_at = datetime('now') WHERE id = ?",
                (result["status"], result["order_id"], fulfillment_id),
            )
            print(f"[ok] order #{row['order_id']} -> {sourced['platform']} order {result['order_id']}")
        except sourcing_providers.SourcingError as e:
            conn.execute(
                "UPDATE fulfillment_orders SET status = 'failed', detail = ?, updated_at = datetime('now') WHERE id = ?",
                (str(e), fulfillment_id),
            )
            print(f"[FAIL] order #{row['order_id']} on {sourced['platform']}: {e}", file=sys.stderr)
        conn.commit()


def main() -> None:
    if not DB_PATH.is_file():
        print(f"[FAIL] panel database not found at {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        links = conn.execute("SELECT * FROM dropship_sites").fetchall()
        for link in links:
            process_site(conn, link)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
