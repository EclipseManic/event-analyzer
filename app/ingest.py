"""EVTX ingestion pipeline for the viewer."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from app.evtx_parser import parse_evtx_file
from app.logger import get_logger
from app import db

logger = get_logger("ingest")


@dataclass
class IngestResult:
    total_events: int
    files_processed: List[str]
    errors: List[str]


def _update_progress(inv_id: str, stage: str, detail: str, percent: int) -> None:
    try:
        db.set_analysis_progress(inv_id, stage, detail, percent)
    except Exception:
        pass


def ingest_files(
    investigation_id: str,
    file_paths: Iterable[str],
    max_events_per_file: int = 0,
    store_raw: bool = False,
    batch_size: int = 2000,
    stop_event: Optional[threading.Event] = None,
) -> IngestResult:
    files = [str(Path(p)) for p in file_paths]
    total_files = len(files)
    total_events = 0
    processed: List[str] = []
    errors: List[str] = []

    db.update_investigation(investigation_id, status="processing")

    for idx, path in enumerate(files, start=1):
        if stop_event and stop_event.is_set():
            break

        percent = int(((idx - 1) / max(1, total_files)) * 100)
        _update_progress(investigation_id, "parsing", f"{Path(path).name} ({idx}/{total_files})", percent)

        batch: List[dict] = []
        file_events = 0
        try:
            for event in parse_evtx_file(path, investigation_id, max_events=max_events_per_file):
                if stop_event and stop_event.is_set():
                    break
                batch.append(event)
                if len(batch) >= batch_size:
                    db.insert_events_bulk(batch)
                    total_events += len(batch)
                    file_events += len(batch)
                    batch.clear()
            if batch:
                db.insert_events_bulk(batch)
                total_events += len(batch)
                file_events += len(batch)
                batch.clear()
        except Exception as exc:
            err = f"{Path(path).name}: {exc}"
            errors.append(err)
            logger.error(err)
            continue

        processed.append(Path(path).name)
        db.update_investigation(
            investigation_id,
            total_events=total_events,
            files_processed=processed,
        )
        _update_progress(
            investigation_id,
            "parsed",
            f"{Path(path).name}: {file_events} events",
            int((idx / max(1, total_files)) * 100),
        )

    status = "complete" if not errors else "complete_with_errors"
    db.update_investigation(investigation_id, status=status, total_events=total_events)
    _update_progress(investigation_id, status, "done", 100)

    return IngestResult(total_events=total_events, files_processed=processed, errors=errors)
