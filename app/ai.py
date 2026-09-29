"""AI Assistant chat — routes only; the actual LLM calls and tool
execution live in ai_engine.py. Each conversation is one row in
ai_conversations: display_json is what the UI renders, raw_json is the
exact provider-format message history needed to keep tool-call context
correct on the next turn, and pending_action_json (when set) blocks new
messages until the admin confirms or cancels the in-flight tool call.
"""
import json

from flask import Blueprint, current_app, flash, g, jsonify, redirect, render_template, request, session

from . import ai_engine
from .security import login_required

bp = Blueprint("ai", __name__)


def _load(row):
    return json.loads(row["display_json"]), json.loads(row["raw_json"]), (
        json.loads(row["pending_action_json"]) if row["pending_action_json"] else None
    )


def _save(db, conv_id, display, raw, pending):
    db.execute(
        "UPDATE ai_conversations SET display_json = ?, raw_json = ?, pending_action_json = ?, updated_at = datetime('now') WHERE id = ?",
        (json.dumps(display), json.dumps(raw), json.dumps(pending) if pending else None, conv_id),
    )
    db.commit()


@bp.route("/ai")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    conversations = g.db.execute("SELECT id, title, updated_at FROM ai_conversations ORDER BY updated_at DESC").fetchall()

    conv_id = request.args.get("c", type=int)
    active = None
    display_messages = []
    pending = None
    if conv_id:
        row = g.db.execute("SELECT * FROM ai_conversations WHERE id = ?", (conv_id,)).fetchone()
        if row:
            active = row
            display_messages, _raw, pending = _load(row)

    return render_template(
        "ai.html",
        ai_enabled=cfg.ai_enabled,
        conversations=conversations,
        active=active,
        display_messages=display_messages,
        pending=pending,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/ai/new", methods=["POST"])
@login_required
def new_conversation():
    cfg = current_app.config["PANEL_CONFIG"]
    cur = g.db.execute("INSERT INTO ai_conversations (title) VALUES ('New chat')")
    g.db.commit()
    return redirect(f"{cfg.dashboard_url}ai?c={cur.lastrowid}")


@bp.route("/ai/delete", methods=["POST"])
@login_required
def delete_conversation():
    cfg = current_app.config["PANEL_CONFIG"]
    conv_id = request.form.get("id", type=int)
    g.db.execute("DELETE FROM ai_conversations WHERE id = ?", (conv_id,))
    g.db.commit()
    return redirect(f"{cfg.dashboard_url}ai")


@bp.route("/ai/send", methods=["POST"])
@login_required
def send():
    cfg = current_app.config["PANEL_CONFIG"]
    conv_id = request.form.get("conversation_id", type=int)
    message = request.form.get("message", "").strip()

    if not cfg.ai_enabled:
        flash("Configure an AI provider and API key in Settings first.", "error")
        return redirect(f"{cfg.dashboard_url}ai")

    row = g.db.execute("SELECT * FROM ai_conversations WHERE id = ?", (conv_id,)).fetchone()
    if not row:
        flash("Conversation not found.", "error")
        return redirect(f"{cfg.dashboard_url}ai")

    display, raw, pending = _load(row)
    if pending:
        flash("Confirm or cancel the pending action before sending another message.", "error")
        return redirect(f"{cfg.dashboard_url}ai?c={conv_id}")
    if not message:
        return redirect(f"{cfg.dashboard_url}ai?c={conv_id}")

    display.append({"role": "user", "text": message})
    raw.append({"role": "user", "content": message})

    if row["title"] == "New chat":
        g.db.execute("UPDATE ai_conversations SET title = ? WHERE id = ?", (message[:60], conv_id))

    try:
        outcome = ai_engine.run_turn(cfg, g.db, raw, display)
    except ai_engine.AIError as e:
        display.append({"role": "assistant", "text": f"⚠️ {e}"})
        outcome = {"status": "done"}

    new_pending = outcome.get("pending") if outcome.get("status") == "needs_confirm" else None
    _save(g.db, conv_id, display, raw, new_pending)
    return redirect(f"{cfg.dashboard_url}ai?c={conv_id}")


def _widget_conversation_id(db) -> int:
    """The floating widget always uses one dedicated conversation per admin
    session (not the full multi-conversation history on the /ai page) —
    a real chat-widget feel, not a conversation manager. Created lazily on
    first use and remembered in the session.
    """
    conv_id = session.get("widget_conversation_id")
    if conv_id:
        row = db.execute("SELECT id FROM ai_conversations WHERE id = ?", (conv_id,)).fetchone()
        if row:
            return conv_id
    cur = db.execute("INSERT INTO ai_conversations (title) VALUES ('Widget chat')")
    db.commit()
    session["widget_conversation_id"] = cur.lastrowid
    return cur.lastrowid


@bp.route("/ai/widget/state")
@login_required
def widget_state():
    cfg = current_app.config["PANEL_CONFIG"]
    conv_id = session.get("widget_conversation_id")
    display, pending = [], None
    if conv_id:
        row = g.db.execute("SELECT * FROM ai_conversations WHERE id = ?", (conv_id,)).fetchone()
        if row:
            display, _raw, pending = _load(row)
    return jsonify({"messages": display, "pending": pending, "ai_enabled": cfg.ai_enabled})


@bp.route("/ai/widget/send", methods=["POST"])
@login_required
def widget_send():
    cfg = current_app.config["PANEL_CONFIG"]
    message = (request.get_json(silent=True) or {}).get("message", "").strip()
    if not message:
        return jsonify({"error": "Message is required."}), 400

    conv_id = _widget_conversation_id(g.db)
    row = g.db.execute("SELECT * FROM ai_conversations WHERE id = ?", (conv_id,)).fetchone()
    display, raw, pending = _load(row)
    if pending:
        return jsonify({"error": "Confirm or cancel the pending action first.", "messages": display, "pending": pending}), 409

    display.append({"role": "user", "text": message})
    raw.append({"role": "user", "content": message})

    try:
        outcome = ai_engine.run_turn(cfg, g.db, raw, display)
    except ai_engine.AIError as e:
        display.append({"role": "assistant", "text": f"⚠️ {e}"})
        outcome = {"status": "done"}

    new_pending = outcome.get("pending") if outcome.get("status") == "needs_confirm" else None
    _save(g.db, conv_id, display, raw, new_pending)
    return jsonify({"messages": display, "pending": new_pending})


@bp.route("/ai/widget/confirm", methods=["POST"])
@login_required
def widget_confirm():
    cfg = current_app.config["PANEL_CONFIG"]
    approved = bool((request.get_json(silent=True) or {}).get("approved"))

    conv_id = session.get("widget_conversation_id")
    row = g.db.execute("SELECT * FROM ai_conversations WHERE id = ?", (conv_id,)).fetchone() if conv_id else None
    if not row:
        return jsonify({"error": "No active chat."}), 404

    display, raw, pending = _load(row)
    if not pending:
        return jsonify({"messages": display, "pending": None})

    try:
        outcome = ai_engine.resume_after_confirmation(cfg, g.db, raw, display, pending, approved)
    except ai_engine.AIError as e:
        display.append({"role": "assistant", "text": f"⚠️ {e}"})
        outcome = {"status": "done"}

    new_pending = outcome.get("pending") if outcome.get("status") == "needs_confirm" else None
    _save(g.db, conv_id, display, raw, new_pending)
    return jsonify({"messages": display, "pending": new_pending})


@bp.route("/ai/widget/new", methods=["POST"])
@login_required
def widget_new():
    g.db.execute("INSERT INTO ai_conversations (title) VALUES ('Widget chat')")
    g.db.commit()
    session["widget_conversation_id"] = g.db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    return jsonify({"messages": [], "pending": None})


@bp.route("/ai/confirm", methods=["POST"])
@login_required
def confirm():
    cfg = current_app.config["PANEL_CONFIG"]
    conv_id = request.form.get("conversation_id", type=int)
    approved = request.form.get("approved") == "on"

    row = g.db.execute("SELECT * FROM ai_conversations WHERE id = ?", (conv_id,)).fetchone()
    if not row:
        flash("Conversation not found.", "error")
        return redirect(f"{cfg.dashboard_url}ai")

    display, raw, pending = _load(row)
    if not pending:
        return redirect(f"{cfg.dashboard_url}ai?c={conv_id}")

    try:
        outcome = ai_engine.resume_after_confirmation(cfg, g.db, raw, display, pending, approved)
    except ai_engine.AIError as e:
        display.append({"role": "assistant", "text": f"⚠️ {e}"})
        outcome = {"status": "done"}

    new_pending = outcome.get("pending") if outcome.get("status") == "needs_confirm" else None
    _save(g.db, conv_id, display, raw, new_pending)
    return redirect(f"{cfg.dashboard_url}ai?c={conv_id}")
