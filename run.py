"""Entrypoint. Production runs this via gunicorn (see systemd/ds-panel.service):
    gunicorn --certfile ... --keyfile ... -b HOST:PORT run:app

Running `python run.py` directly starts Flask's own dev server with the
same TLS cert, for local development only.
"""
from app import create_app
from app.config import load_config

app = create_app()

if __name__ == "__main__":
    cfg = load_config()
    app.run(host=cfg.host, port=cfg.port, ssl_context=(cfg.ssl_cert, cfg.ssl_key))
