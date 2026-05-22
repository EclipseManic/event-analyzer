"""Flask API for Event-Analyzer."""

from __future__ import annotations

import io
import json
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from app.config import get_config
from app.ingest import ingest_files
from app.logger import get_logger
from app.utils import has_evtx_magic
from app import db

logger = get_logger("api")

_INGEST_SEM = threading.Semaphore(get_config().concurrent_ingest)


def create_app() -> Flask:
    cfg = get_config()
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_request_mb * 1024 * 1024

    @app.errorhandler(RequestEntityTooLarge)
    def _handle_file_too_large(_err: Exception):
        return jsonify({"error": "upload_too_large"}), 413

    @app.get("/")
    def index():
        return render_template("index.html", page_limit=cfg.page_limit)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/investigations")
    def list_investigations():
        return jsonify(db.list_investigations())

    @app.get("/api/investigations/<inv_id>")
    def get_investigation(inv_id: str):
        result = db.get_investigation(inv_id)
        if not result:
            return jsonify({"error": "not_found"}), 404
        return jsonify(result)

    @app.delete("/api/investigations/<inv_id>")
    def delete_investigation(inv_id: str):
        existing = db.get_investigation(inv_id)
        if not existing:
            return jsonify({"error": "not_found"}), 404
        if existing.get("status") == "deleting":
            return jsonify({"status": "deleting"}), 202

        db.update_investigation(inv_id, status="deleting")

        def _purge() -> None:
            try:
                db.delete_investigation(inv_id)
            except Exception as exc:
                logger.error("Failed to delete investigation %s: %s", inv_id, exc)
            try:
                shutil.rmtree(cfg.uploads_dir / inv_id, ignore_errors=True)
            except Exception as exc:
                logger.warning("Failed to remove uploads for %s: %s", inv_id, exc)

        thread = threading.Thread(target=_purge, name=f"delete-{inv_id[:8]}", daemon=True)
        thread.start()
        return jsonify({"status": "deleting"}), 202

    @app.get("/api/investigations/<inv_id>/progress")
    def get_progress(inv_id: str):
        progress = db.get_analysis_progress(inv_id)
        if not progress:
            return jsonify({"stage": "unknown", "percent": 0})
        return jsonify(progress)

    @app.get("/api/investigations/<inv_id>/events")
    def get_events(inv_id: str):
        filters, sort, limit, offset = _parse_event_query()
        rows = db.get_events(inv_id, filters=filters, limit=limit, offset=offset, sort=sort)
        return jsonify(rows)

    @app.get("/api/investigations/<inv_id>/events/count")
    def get_event_count(inv_id: str):
        filters, _, _, _ = _parse_event_query()
        return jsonify({"count": db.get_event_count(inv_id, filters=filters)})

    @app.get("/api/investigations/<inv_id>/events/<event_id>")
    def get_event_detail(inv_id: str, event_id: str):
        row = db.get_event_detail(inv_id, event_id)
        if not row:
            return jsonify({"error": "not_found"}), 404
        return jsonify(row)

    @app.get("/api/investigations/<inv_id>/channels")
    def get_channels(inv_id: str):
        return jsonify(db.get_channels(inv_id))

    @app.get("/api/investigations/<inv_id>/providers")
    def get_providers(inv_id: str):
        return jsonify(db.get_providers(inv_id))

    @app.get("/api/investigations/<inv_id>/source-files")
    def get_source_files(inv_id: str):
        return jsonify(db.get_source_files(inv_id))

    @app.get("/api/investigations/<inv_id>/timeline")
    def get_timeline(inv_id: str):
        bucket = _safe_int(request.args.get("bucket"), 60)
        filters, _, _, _ = _parse_event_query()
        return jsonify(db.get_timeline_buckets(inv_id, bucket_minutes=bucket, filters=filters))

    @app.get("/api/investigations/<inv_id>/events/export")
    def export_events(inv_id: str):
        fmt = (request.args.get("format") or "csv").strip().lower()
        filters, sort, _, _ = _parse_event_query()
        if fmt == "json":
            return _export_json(inv_id, filters, sort)
        return _export_csv(inv_id, filters, sort)

    @app.post("/api/upload")
    def upload_evtx():
        cfg = get_config()
        files = request.files.getlist("files")
        if not files:
            return jsonify({"error": "no_files"}), 400
        if len(files) > cfg.max_files_per_upload:
            return jsonify({"error": "too_many_files", "max": cfg.max_files_per_upload}), 400

        name = (request.form.get("name") or "").strip()
        if not name:
            name = _default_investigation_name(files)

        inv_id = db.create_investigation(name, [])
        upload_dir = cfg.uploads_dir / inv_id
        upload_dir.mkdir(parents=True, exist_ok=True)

        saved_files: List[str] = []
        errors: List[str] = []
        for file in files:
            filename = secure_filename(file.filename or "")
            if not filename.lower().endswith(".evtx"):
                errors.append(f"{filename or 'unknown'}: invalid extension")
                continue

            target = upload_dir / filename
            if target.exists():
                target = upload_dir / f"{target.stem}_{int(time.time())}{target.suffix}"

            try:
                size = _save_upload(file, target, cfg.max_upload_mb)
            except ValueError as exc:
                errors.append(str(exc))
                continue

            if size == 0:
                errors.append(f"{filename}: empty file")
                target.unlink(missing_ok=True)
                continue

            if not has_evtx_magic(target):
                errors.append(f"{filename}: invalid EVTX magic")
                target.unlink(missing_ok=True)
                continue

            saved_files.append(str(target))

        if not saved_files:
            db.update_investigation(inv_id, status="failed", error_count=len(errors))
            return jsonify({"error": "no_valid_files", "details": errors}), 400

        db.update_investigation(inv_id, files_processed=[Path(p).name for p in saved_files])

        def _runner() -> None:
            with _INGEST_SEM:
                ingest_files(
                    investigation_id=inv_id,
                    file_paths=saved_files,
                    max_events_per_file=cfg.max_events_per_file,
                    store_raw=cfg.store_raw,
                )

        thread = threading.Thread(target=_runner, name=f"ingest-{inv_id[:8]}", daemon=True)
        thread.start()

        response = {
            "investigation_id": inv_id,
            "files": [Path(p).name for p in saved_files],
            "errors": errors,
        }
        return jsonify(response)

    return app


def _save_upload(file, target: Path, max_mb: int) -> int:
    max_bytes = int(max_mb) * 1024 * 1024
    size = 0
    with target.open("wb") as handle:
        while True:
            chunk = file.stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                target.unlink(missing_ok=True)
                raise ValueError(f"{target.name}: exceeds {max_mb} MB limit")
            handle.write(chunk)
    return size


def _default_investigation_name(files) -> str:
    for file in files:
        raw = (file.filename or "").strip()
        if not raw:
            continue
        base = Path(raw).name
        stem = Path(base).stem
        return stem or base
    return f"Investigation {int(time.time())}"


def _parse_event_query() -> tuple[Dict[str, Any], str, int, int]:
    cfg = get_config()
    args = request.args
    filters: Dict[str, Any] = {}
    for key in (
        "event_id",
        "channel",
        "provider",
        "user_name",
        "hostname",
        "source_file",
        "search",
        "start_time",
        "end_time",
    ):
        val = args.get(key)
        if val:
            filters[key] = val

    sort = (args.get("sort") or "asc").strip().lower()
    limit = _safe_int(args.get("limit"), cfg.page_limit)
    offset = _safe_int(args.get("offset"), 0)

    limit = max(1, min(limit, 5000))
    offset = max(0, offset)

    return filters, sort, limit, offset


def _safe_int(raw: Any, default: int) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _export_csv(inv_id: str, filters: Dict[str, Any], sort: str) -> Response:
    import csv

    def generate():
        output = io.StringIO()
        writer = csv.writer(output)
        header = [
            "timestamp",
            "event_id",
            "level",
            "channel",
            "provider",
            "computer",
            "hostname",
            "user_name",
            "process_name",
            "command_line",
            "source_ip",
            "dest_ip",
            "file_path",
            "source_file",
            "event_record_id",
            "description",
        ]
        writer.writerow(header)
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        for row in db.iter_events(inv_id, filters=filters, sort=sort):
            writer.writerow([row.get(col) for col in header])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={inv_id}_events.csv"},
    )


def _export_json(inv_id: str, filters: Dict[str, Any], sort: str) -> Response:
    def generate():
        yield "["
        first = True
        for row in db.iter_events(inv_id, filters=filters, sort=sort):
            payload = json.dumps(row)
            if not first:
                yield ","
            yield payload
            first = False
        yield "]"

    return Response(
        generate(),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={inv_id}_events.json"},
    )
