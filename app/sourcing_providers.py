"""Adapters for Chinese marketplace sourcing (1688, AliExpress, Taobao).

None of these platforms expose a simple, standardized public API — real
access always goes through either an official Open Platform account
(business verification, Chinese-language docs, 1688/Taobao specifically) or
a third-party aggregator/reseller API (common for AliExpress dropshipping
tools). Since the exact endpoint paths and request/response field names
depend entirely on which specific provider account the admin signs up
with, this module defines one clean interface plus a generic HTTP/JSON
adapter configured per-provider (base URL + key/secret) rather than
hardcoding a contract — the field-mapping in each function below is a
REASONABLE GUESS at a typical aggregator's shape, not a verified
integration with a specific real provider. Confirm and adjust the field
names once you have your chosen provider's actual API documentation.
"""
import requests


class SourcingError(RuntimeError):
    pass


def _request(provider: dict, method: str, path: str, **kwargs) -> dict:
    if not provider or not provider["enabled"]:
        name = provider["platform"] if provider else "This provider"
        raise SourcingError(f"{name} isn't configured — add an API key under Dropshipping → Providers first.")
    if not provider["api_base_url"]:
        raise SourcingError(f"{provider['platform']}: no API base URL configured.")

    url = provider["api_base_url"].rstrip("/") + path
    headers = kwargs.pop("headers", {})
    headers.setdefault("Authorization", f"Bearer {provider['app_secret']}")
    headers.setdefault("X-App-Key", provider["app_key"])

    try:
        resp = requests.request(method, url, headers=headers, timeout=20, **kwargs)
    except requests.RequestException as e:
        raise SourcingError(f"Could not reach {provider['platform']} API: {e}") from e

    if resp.status_code != 200:
        raise SourcingError(f"{provider['platform']} API error ({resp.status_code}): {resp.text[:300]}")
    try:
        return resp.json()
    except ValueError:
        raise SourcingError(f"{provider['platform']} API returned a non-JSON response.")


def search_products(provider: dict, keyword: str, page: int = 1) -> list[dict]:
    """Normalized to {id, title, price, image, url} regardless of provider —
    adjust the .get() field names below to match your real provider's
    actual response once you have it.
    """
    data = _request(provider, "GET", "/search", params={"q": keyword, "page": page})
    items = data.get("items") or data.get("data") or data.get("results") or []
    results = []
    for item in items:
        results.append({
            "id": str(item.get("id") or item.get("product_id") or item.get("num_iid") or ""),
            "title": item.get("title") or item.get("name") or item.get("subject") or "",
            "price": float(item.get("price") or item.get("min_price") or item.get("promotion_price") or 0),
            "image": item.get("image") or item.get("main_image") or item.get("pic_url") or "",
            "url": item.get("url") or item.get("detail_url") or item.get("item_url") or "",
        })
    return results


def get_product_detail(provider: dict, product_id: str) -> dict:
    data = _request(provider, "GET", f"/product/{product_id}")
    return data.get("data", data)


def place_order(provider: dict, product_id: str, quantity: int, shipping_address: dict) -> dict:
    """Returns {"order_id": ..., "status": ...} on success. This is the
    part most likely to need real adjustment — order-creation payloads
    vary the most between providers (address field names, payment
    handling, SKU/variant selection).
    """
    payload = {"product_id": product_id, "quantity": quantity, "address": shipping_address}
    data = _request(provider, "POST", "/order/create", json=payload)
    return {
        "order_id": str(data.get("order_id") or data.get("id") or ""),
        "status": data.get("status", "placed"),
    }


def get_order_status(provider: dict, source_order_id: str) -> dict:
    data = _request(provider, "GET", f"/order/{source_order_id}")
    return {
        "status": data.get("status", "unknown"),
        "tracking_number": data.get("tracking_number") or data.get("tracking_no") or "",
    }
