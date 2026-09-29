"""Direct MySQL access to a site's OpenCart database, for the Dropshipping
feature's product import and order fulfillment lookup — parameterized via
pymysql rather than shelling out to `mysql -e` with hand-built SQL
strings, since product data comes from an external API and can contain
quotes/unicode that's risky to interpolate into raw SQL text.

Connects as the OS root user via MySQL's auth_socket plugin — the same
passwordless root access `mysql -u root` already relies on everywhere else
in system_ops.py, since this panel process itself runs as root.
"""
from datetime import datetime

import pymysql
import pymysql.cursors

MYSQL_SOCKET = "/var/run/mysqld/mysqld.sock"


class OpenCartDbError(RuntimeError):
    pass


def _connect(db_name: str):
    try:
        return pymysql.connect(
            unix_socket=MYSQL_SOCKET,
            user="root",
            database=db_name,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
            charset="utf8mb4",
        )
    except pymysql.MySQLError as e:
        raise OpenCartDbError(f"Could not connect to database {db_name!r}: {e}") from e


def insert_product(db_name: str, title: str, description: str, price: float, model: str, image_path: str = "") -> int:
    """Inserts a minimal but storefront-visible OpenCart product
    (oc_product + oc_product_description + oc_product_to_store) and
    returns the new product_id. Assumes OpenCart's default "oc_" table
    prefix and language_id 1 (English) — matches how this panel's own App
    Store installer sets up OpenCart (see system_ops.install_opencart).
    """
    conn = _connect(db_name)
    try:
        with conn.cursor() as cur:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur.execute(
                "INSERT INTO oc_product (model, quantity, stock_status_id, image, price, status, "
                "date_available, date_added, date_modified) VALUES (%s, %s, %s, %s, %s, 1, %s, %s, %s)",
                (model[:64], 100, 7, image_path, price, now, now, now),
            )
            product_id = cur.lastrowid

            cur.execute(
                "INSERT INTO oc_product_description (product_id, language_id, name, description, meta_title) "
                "VALUES (%s, 1, %s, %s, %s)",
                (product_id, title[:255], description, title[:255]),
            )
            cur.execute("INSERT INTO oc_product_to_store (product_id, store_id) VALUES (%s, 0)", (product_id,))
        return product_id
    except pymysql.MySQLError as e:
        raise OpenCartDbError(f"Product insert failed: {e}") from e
    finally:
        conn.close()


def fetch_new_orders(db_name: str, product_ids: list[int]) -> list[dict]:
    """Orders that are actually paid/confirmed (order_status_id > 0 — not
    an abandoned cart) containing at least one of the given OpenCart
    product IDs. Used by the fulfillment poller to find work to do.
    """
    if not product_ids:
        return []
    conn = _connect(db_name)
    try:
        with conn.cursor() as cur:
            placeholders = ",".join(["%s"] * len(product_ids))
            cur.execute(
                "SELECT o.order_id, o.email, o.telephone, o.shipping_address_1, o.shipping_address_2, "
                "o.shipping_city, o.shipping_postcode, o.shipping_country, o.shipping_zone, "
                f"op.product_id, op.quantity FROM oc_order o "
                f"JOIN oc_order_product op ON op.order_id = o.order_id "
                f"WHERE o.order_status_id > 0 AND op.product_id IN ({placeholders})",
                product_ids,
            )
            return cur.fetchall()
    except pymysql.MySQLError as e:
        raise OpenCartDbError(f"Order lookup failed: {e}") from e
    finally:
        conn.close()
