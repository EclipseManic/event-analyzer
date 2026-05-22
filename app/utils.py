"""Shared helpers for Event-Analyzer."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

_EVTX_MAGIC = b"ElfFile\x00"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def has_evtx_magic(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(8) == _EVTX_MAGIC
    except OSError:
        return False
