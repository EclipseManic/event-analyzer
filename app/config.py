"""Configuration for Event-Analyzer."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None


_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH = _ROOT / "settings" / ".env"

if load_dotenv is not None and _ENV_PATH.exists():
    load_dotenv(_ENV_PATH)


@dataclass(frozen=True)
class ViewerConfig:
    host: str
    port: int
    debug: bool
    auto_launch: bool
    max_upload_mb: int
    max_files_per_upload: int
    max_request_mb: int
    page_limit: int
    max_events_per_file: int
    store_raw: bool
    concurrent_ingest: int
    data_dir: Path
    db_path: Path
    uploads_dir: Path


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip() or default


def _env_int(name: str, default: int, min_value: int | None = None) -> int:
    raw = os.environ.get(name)
    if raw is None:
        value = default
    else:
        try:
            value = int(raw)
        except ValueError:
            value = default
    if min_value is not None:
        value = max(min_value, value)
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    val = raw.strip().lower()
    if val in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if val in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


_cached: ViewerConfig | None = None


def get_config() -> ViewerConfig:
    global _cached
    if _cached is not None:
        return _cached

    data_dir = Path(_env_str("EVTX_VIEWER_DATA_DIR", str(_ROOT / "data" / "evtx_viewer")))
    db_path = Path(_env_str("EVTX_VIEWER_DB_PATH", str(data_dir / "evtx_viewer.db")))
    uploads_dir = Path(_env_str("EVTX_VIEWER_UPLOADS_DIR", str(data_dir / "uploads")))

    cfg = ViewerConfig(
        host=_env_str("EVTX_VIEWER_HOST", "127.0.0.1"),
        port=_env_int("EVTX_VIEWER_PORT", 5050, min_value=1),
        debug=_env_bool("EVTX_VIEWER_DEBUG", False),
        auto_launch=_env_bool("EVTX_VIEWER_AUTO_LAUNCH", True),
        max_upload_mb=_env_int("EVTX_VIEWER_MAX_UPLOAD_MB", 100, min_value=1),
        max_files_per_upload=_env_int("EVTX_VIEWER_MAX_FILES", 500, min_value=1),
        max_request_mb=_env_int("EVTX_VIEWER_MAX_REQUEST_MB", 2048, min_value=1),
        page_limit=_env_int("EVTX_VIEWER_PAGE_LIMIT", 200, min_value=1),
        max_events_per_file=_env_int("EVTX_VIEWER_MAX_EVENTS_PER_FILE", 0, min_value=0),
        store_raw=_env_bool("EVTX_VIEWER_STORE_RAW", False),
        concurrent_ingest=_env_int("EVTX_VIEWER_CONCURRENT_INGEST", 2, min_value=1),
        data_dir=data_dir,
        db_path=db_path,
        uploads_dir=uploads_dir,
    )

    _cached = cfg
    return cfg
