"""Event-Analyzer entry point."""

from __future__ import annotations

import webbrowser

from app.api import create_app
from app.config import get_config
from app.db import init_db
from app.logger import setup_logging


def main() -> None:
    cfg = get_config()
    setup_logging()
    init_db()
    app = create_app()

    if cfg.auto_launch and not cfg.debug:
        try:
            webbrowser.open(f"http://{cfg.host}:{cfg.port}")
        except Exception:
            pass

    app.run(host=cfg.host, port=cfg.port, debug=cfg.debug)


if __name__ == "__main__":
    main()
