"""SQLite database layer for Event-Analyzer."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from app.config import get_config
from app.logger import get_logger
from app.utils import now_iso

logger = get_logger("db")

_cfg = get_config()
DB_PATH = _cfg.db_path
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_db_initialized = False
_db_init_lock = threading.Lock()
_thread_local = threading.local()

_fts_enabled = False
_TIME_FILTER_RE = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2})"
    r"(?:[ T]+(\d{2})(?::(\d{2})(?::(\d{2})(?:\.(\d{1,7}))?)?)?)?"
    r"\s*(Z|[+-]\d{2}(?::?\d{2})?)?\s*$",
    re.IGNORECASE,
)
_FRACTION_TICKS = 10_000_000  # 100ns ticks in one second


def _get_conn() -> sqlite3.Connection:
    conn = getattr(_thread_local, "conn", None)
    if conn is not None:
        return conn
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _thread_local.conn = conn
    return conn


def init_db() -> None:
    global _db_initialized, _fts_enabled
    with _db_init_lock:
        if _db_initialized:
            return
        conn = _get_conn()
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                total_events INTEGER DEFAULT 0,
                files_processed TEXT DEFAULT '[]',
                error_count INTEGER DEFAULT 0,
                last_error TEXT
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_id INTEGER,
                level INTEGER,
                channel TEXT,
                provider TEXT,
                computer TEXT,
                hostname TEXT,
                user_name TEXT,
                user_domain TEXT,
                process_name TEXT,
                process_id INTEGER,
                parent_process TEXT,
                command_line TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                logon_type TEXT,
                target_user TEXT,
                target_domain TEXT,
                file_path TEXT,
                registry_key TEXT,
                registry_value TEXT,
                service_name TEXT,
                hash_value TEXT,
                event_category TEXT,
                task TEXT,
                opcode TEXT,
                keywords TEXT,
                description TEXT,
                raw_data TEXT,
                source_file TEXT,
                event_record_id INTEGER,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id)
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_progress (
                investigation_id TEXT PRIMARY KEY,
                stage TEXT NOT NULL,
                detail TEXT,
                percent INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id)
            )
            """
        )

        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_inv ON events(investigation_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_channel ON events(channel)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_provider ON events(provider)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(hostname)")

        try:
            cur.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                    id UNINDEXED,
                    investigation_id UNINDEXED,
                    searchtext,
                    tokenize='trigram case_sensitive 0'
                )
                """
            )
            _fts_enabled = True
        except Exception:
            _fts_enabled = False

        conn.commit()
        _db_initialized = True


def create_investigation(name: str, files: List[str] | None = None) -> str:
    inv_id = _new_id()
    conn = _get_conn()
    conn.execute(
        "INSERT INTO investigations (id, name, created_at, status, files_processed) VALUES (?, ?, ?, ?, ?)",
        (inv_id, name, now_iso(), "pending", json.dumps(files or [])),
    )
    conn.commit()
    return inv_id


def update_investigation(inv_id: str, **kwargs: Any) -> None:
    allowed = {"name", "status", "total_events", "files_processed", "error_count", "last_error"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if "files_processed" in updates and isinstance(updates["files_processed"], list):
        updates["files_processed"] = json.dumps(updates["files_processed"])
    if not updates:
        return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [inv_id]
    conn = _get_conn()
    conn.execute(f"UPDATE investigations SET {set_clause} WHERE id = ?", values)
    conn.commit()


def get_investigation(inv_id: str) -> Optional[Dict[str, Any]]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    if not row:
        return None
    data = dict(row)
    raw = data.get("files_processed")
    if isinstance(raw, str):
        try:
            data["files_processed"] = json.loads(raw)
        except json.JSONDecodeError:
            pass
    return data


def list_investigations() -> List[Dict[str, Any]]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM investigations WHERE status != 'deleting' ORDER BY created_at DESC"
    ).fetchall()
    results = []
    for row in rows:
        data = dict(row)
        raw = data.get("files_processed")
        if isinstance(raw, str):
            try:
                data["files_processed"] = json.loads(raw)
            except json.JSONDecodeError:
                pass
        results.append(data)
    return results


def delete_investigation(inv_id: str) -> bool:
    conn = _get_conn()
    row = conn.execute("SELECT id FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    if not row:
        return False
    conn.execute("DELETE FROM events WHERE investigation_id = ?", (inv_id,))
    conn.execute("DELETE FROM analysis_progress WHERE investigation_id = ?", (inv_id,))
    conn.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
    try:
        conn.execute("DELETE FROM events_fts WHERE investigation_id = ?", (inv_id,))
    except Exception:
        pass
    conn.commit()
    return True


def set_analysis_progress(inv_id: str, stage: str, detail: str, percent: int) -> None:
    conn = _get_conn()
    pct = max(0, min(100, int(percent)))
    conn.execute(
        """
        INSERT INTO analysis_progress (investigation_id, stage, detail, percent, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(investigation_id) DO UPDATE SET
            stage = excluded.stage,
            detail = excluded.detail,
            percent = excluded.percent,
            updated_at = excluded.updated_at
        """,
        (inv_id, stage or "pending", detail or "", pct, now_iso()),
    )
    conn.commit()


def get_analysis_progress(inv_id: str) -> Optional[Dict[str, Any]]:
    conn = _get_conn()
    row = conn.execute(
        "SELECT investigation_id, stage, detail, percent, updated_at FROM analysis_progress WHERE investigation_id = ?",
        (inv_id,),
    ).fetchone()
    return dict(row) if row else None


def insert_events_bulk(events: List[Dict[str, Any]], batch_size: int = 1000) -> int:
    if not events:
        return 0
    conn = _get_conn()
    count = 0
    columns = [
        "id",
        "investigation_id",
        "timestamp",
        "event_id",
        "level",
        "channel",
        "provider",
        "computer",
        "hostname",
        "user_name",
        "user_domain",
        "process_name",
        "process_id",
        "parent_process",
        "command_line",
        "source_ip",
        "dest_ip",
        "source_port",
        "dest_port",
        "logon_type",
        "target_user",
        "target_domain",
        "file_path",
        "registry_key",
        "registry_value",
        "service_name",
        "hash_value",
        "event_category",
        "task",
        "opcode",
        "keywords",
        "description",
        "raw_data",
        "source_file",
        "event_record_id",
    ]
    placeholders = ",".join("?" for _ in columns)
    sql = f"INSERT OR IGNORE INTO events ({', '.join(columns)}) VALUES ({placeholders})"

    def _row(evt: Dict[str, Any]) -> tuple:
        return (
            evt.get("id", _new_id()),
            evt.get("investigation_id", ""),
            evt.get("timestamp", ""),
            evt.get("event_id"),
            evt.get("level"),
            evt.get("channel"),
            evt.get("provider"),
            evt.get("computer") or evt.get("hostname"),
            evt.get("hostname") or evt.get("computer"),
            evt.get("user_name"),
            evt.get("user_domain"),
            evt.get("process_name"),
            evt.get("process_id"),
            evt.get("parent_process"),
            evt.get("command_line"),
            evt.get("source_ip"),
            evt.get("dest_ip"),
            evt.get("source_port"),
            evt.get("dest_port"),
            evt.get("logon_type"),
            evt.get("target_user"),
            evt.get("target_domain"),
            evt.get("file_path"),
            evt.get("registry_key"),
            evt.get("registry_value"),
            evt.get("service_name"),
            evt.get("hash_value"),
            evt.get("event_category"),
            evt.get("task"),
            evt.get("opcode"),
            evt.get("keywords"),
            evt.get("description"),
            evt.get("raw_data"),
            evt.get("source_file"),
            evt.get("event_record_id"),
        )

    for i in range(0, len(events), batch_size):
        batch = events[i:i + batch_size]
        rows = [_row(evt) for evt in batch]
        conn.executemany(sql, rows)
        count += len(rows)

    conn.commit()

    if _fts_enabled:
        fts_rows = []
        for evt in events:
            searchtext = " ".join(
                filter(
                    None,
                    [
                        str(evt.get("description") or ""),
                        str(evt.get("command_line") or ""),
                        str(evt.get("user_name") or ""),
                        str(evt.get("process_name") or ""),
                        str(evt.get("file_path") or ""),
                        str(evt.get("provider") or ""),
                        str(evt.get("channel") or ""),
                    ],
                )
            )
            fts_rows.append(
                (
                    evt.get("id", ""),
                    evt.get("investigation_id", ""),
                    searchtext,
                )
            )
        try:
            conn.executemany(
                "INSERT OR IGNORE INTO events_fts(id, investigation_id, searchtext) VALUES (?,?,?)",
                fts_rows,
            )
            conn.commit()
        except Exception:
            pass

    return count


def get_events(
    investigation_id: str,
    filters: Dict[str, Any] | None = None,
    limit: int = 1000,
    offset: int = 0,
    sort: str = "asc",
) -> List[Dict[str, Any]]:
    conn = _get_conn()
    query = (
        "SELECT id, investigation_id, timestamp, event_id, level, channel, provider, computer, "
        "hostname, user_name, user_domain, process_name, process_id, parent_process, command_line, "
        "source_ip, dest_ip, source_port, dest_port, logon_type, target_user, target_domain, file_path, "
        "registry_key, registry_value, service_name, hash_value, event_category, task, opcode, keywords, "
        "description, source_file, event_record_id "
        "FROM events WHERE investigation_id = ?"
    )
    params: List[Any] = [investigation_id]
    query, params = _apply_filters(query, params, filters or {})

    sort_dir = "DESC" if str(sort).strip().lower() == "desc" else "ASC"
    query += f" ORDER BY timestamp {sort_dir} LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_event_count(investigation_id: str, filters: Dict[str, Any] | None = None) -> int:
    conn = _get_conn()
    query = "SELECT COUNT(*) AS cnt FROM events WHERE investigation_id = ?"
    params: List[Any] = [investigation_id]
    query, params = _apply_filters(query, params, filters or {})
    row = conn.execute(query, params).fetchone()
    return int(row["cnt"] if row else 0)


def get_event_detail(investigation_id: str, event_id: str) -> Optional[Dict[str, Any]]:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM events WHERE investigation_id = ? AND id = ?",
        (investigation_id, event_id),
    ).fetchone()
    return dict(row) if row else None


def iter_events(
    investigation_id: str,
    filters: Dict[str, Any] | None = None,
    columns: List[str] | None = None,
    sort: str = "asc",
) -> Iterable[Dict[str, Any]]:
    conn = _get_conn()
    if columns is None:
        columns = [
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
    col_list = ", ".join(columns)
    query = f"SELECT {col_list} FROM events WHERE investigation_id = ?"
    params: List[Any] = [investigation_id]
    query, params = _apply_filters(query, params, filters or {})
    sort_dir = "DESC" if str(sort).strip().lower() == "desc" else "ASC"
    query += f" ORDER BY timestamp {sort_dir}"

    cur = conn.execute(query, params)
    while True:
        rows = cur.fetchmany(1000)
        if not rows:
            break
        for row in rows:
            yield dict(row)


def get_channels(investigation_id: str) -> List[str]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT DISTINCT channel FROM events WHERE investigation_id = ? AND channel IS NOT NULL ORDER BY channel",
        (investigation_id,),
    ).fetchall()
    return [r["channel"] for r in rows]


def get_providers(investigation_id: str) -> List[str]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT DISTINCT provider FROM events WHERE investigation_id = ? AND provider IS NOT NULL ORDER BY provider",
        (investigation_id,),
    ).fetchall()
    return [r["provider"] for r in rows]


def get_source_files(investigation_id: str) -> List[str]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT DISTINCT source_file FROM events WHERE investigation_id = ? AND source_file IS NOT NULL ORDER BY source_file",
        (investigation_id,),
    ).fetchall()
    return [r["source_file"] for r in rows]


def get_timeline_buckets(
    investigation_id: str,
    bucket_minutes: int = 60,
    filters: Dict[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    conn = _get_conn()
    if bucket_minutes >= 1440:
        bucket_expr = "SUBSTR(timestamp, 1, 10)"
    elif bucket_minutes >= 60:
        bucket_expr = "SUBSTR(timestamp, 1, 13)"
    elif bucket_minutes >= 10:
        bucket_expr = (
            "SUBSTR(timestamp, 1, 14) || "
            "printf('%02d', (CAST(SUBSTR(timestamp, 15, 2) AS INTEGER) / 10) * 10)"
        )
    else:
        bucket_expr = "SUBSTR(timestamp, 1, 16)"

    query = (
        f"SELECT {bucket_expr} AS time_bucket, COUNT(*) AS count "
        "FROM events WHERE investigation_id = ? AND timestamp IS NOT NULL AND timestamp != ''"
    )
    params: List[Any] = [investigation_id]
    query, params = _apply_filters(query, params, filters or {})
    query += " GROUP BY time_bucket ORDER BY time_bucket ASC"
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def _apply_filters(query: str, params: List[Any], filters: Dict[str, Any]) -> tuple[str, List[Any]]:
    if not filters:
        return query, params

    if filters.get("event_id"):
        try:
            event_id_val = int(str(filters["event_id"]).strip())
        except (TypeError, ValueError):
            query += " AND 1 = 0"
        else:
            query += " AND event_id = ?"
            params.append(event_id_val)

    if filters.get("channel"):
        query += " AND channel = ?"
        params.append(filters["channel"])

    if filters.get("provider"):
        query += " AND provider = ?"
        params.append(filters["provider"])

    if filters.get("user_name"):
        query += " AND user_name = ?"
        params.append(filters["user_name"])

    if filters.get("hostname"):
        query += " AND (hostname = ? OR computer = ?)"
        params.extend([filters["hostname"], filters["hostname"]])

    if filters.get("source_file"):
        query += " AND source_file = ?"
        params.append(filters["source_file"])

    if filters.get("start_time"):
        start_bound = _normalize_time_filter_bound(filters["start_time"], "start")
        if start_bound:
            query += " AND julianday(timestamp) >= julianday(?)"
            params.append(start_bound)

    if filters.get("end_time"):
        end_bound = _normalize_time_filter_bound(filters["end_time"], "end_exclusive")
        if end_bound:
            query += " AND julianday(timestamp) < julianday(?)"
            params.append(end_bound)

    if filters.get("search"):
        term = str(filters["search"]).strip()
        if term:
            # Always add a substring (LIKE) match so searches behave like *term*
            search_wc = f"%{term}%"
            like_clause = (
                " AND (description LIKE ? OR command_line LIKE ? OR user_name LIKE ? OR file_path LIKE ? OR timestamp LIKE ? OR raw_data LIKE ?)"
            )
            # If FTS is available and term looks safe, include FTS matches as an OR to use the index when possible.
            if _fts_enabled and len(term) >= 3 and _is_safe_fts_term(term):
                # Use either FTS MATCH or the LIKE clause to find matches
                query += (
                    " AND (id IN (SELECT id FROM events_fts WHERE events_fts MATCH ? AND investigation_id = ?)" +
                    " OR (description LIKE ? OR command_line LIKE ? OR user_name LIKE ? OR file_path LIKE ? OR timestamp LIKE ? OR raw_data LIKE ?))"
                )
                params.extend([term, params[0]])
                params.extend([search_wc] * 6)
            else:
                query += like_clause
                params.extend([search_wc] * 6)

    return query, params


def _is_safe_fts_term(term: str) -> bool:
    return bool(term) and all(ch.isalnum() or ch.isspace() or ch == "_" for ch in term)


def _normalize_time_filter_bound(raw_value: Any, bound: str) -> Optional[str]:
    parsed = _parse_time_filter(raw_value)
    if not parsed:
        return None

    dt = parsed["dt"]
    ticks = parsed["ticks"]
    precision = parsed["precision"]
    fraction_digits = parsed["fraction_digits"]

    if bound == "end_exclusive":
        if precision == "day":
            dt += timedelta(days=1)
            ticks = 0
        elif precision == "hour":
            dt += timedelta(hours=1)
            ticks = 0
        elif precision == "minute":
            dt += timedelta(minutes=1)
            ticks = 0
        elif precision == "second":
            dt += timedelta(seconds=1)
            ticks = 0
        else:
            step = 10 ** (7 - fraction_digits)
            ticks += step
            if ticks >= _FRACTION_TICKS:
                dt += timedelta(seconds=1)
                ticks -= _FRACTION_TICKS

    return _format_time_filter_value(dt, ticks)


def _parse_time_filter(raw_value: Any) -> Optional[Dict[str, Any]]:
    raw = str(raw_value or "").strip()
    if not raw:
        return None

    match = _TIME_FILTER_RE.match(raw)
    if not match:
        return None

    date_part, hour_raw, minute_raw, second_raw, fraction_raw, zone_raw = match.groups()
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_part):
        return None

    year, month, day = [int(part) for part in date_part.split("-")]
    hour = int(hour_raw) if hour_raw is not None else 0
    minute = int(minute_raw) if minute_raw is not None else 0
    second = int(second_raw) if second_raw is not None else 0

    if hour_raw is None:
        precision = "day"
    elif minute_raw is None:
        precision = "hour"
    elif second_raw is None:
        precision = "minute"
    elif fraction_raw is None:
        precision = "second"
    else:
        precision = "fraction"

    fraction_digits = len(fraction_raw or "")
    ticks = int((fraction_raw or "").ljust(7, "0")) if fraction_raw else 0

    try:
        dt = datetime(year, month, day, hour, minute, second)
    except ValueError:
        return None

    if zone_raw:
        tzinfo = _parse_timezone_offset(zone_raw)
        if tzinfo is None:
            return None
        dt = dt.replace(tzinfo=tzinfo).astimezone(timezone.utc).replace(tzinfo=None)

    return {
        "dt": dt,
        "ticks": ticks,
        "precision": precision,
        "fraction_digits": fraction_digits,
    }


def _parse_timezone_offset(raw_zone: str) -> Optional[timezone]:
    zone = str(raw_zone).strip()
    if zone.upper() == "Z":
        return timezone.utc

    match = re.match(r"^([+-])(\d{2})(?::?(\d{2}))?$", zone)
    if not match:
        return None

    sign, hour_raw, minute_raw = match.groups()
    hours = int(hour_raw)
    minutes = int(minute_raw or "00")
    if hours > 23 or minutes > 59:
        return None

    offset = timedelta(hours=hours, minutes=minutes)
    if sign == "-":
        offset = -offset
    return timezone(offset)


def _format_time_filter_value(dt: datetime, ticks: int) -> str:
    base = dt.strftime("%Y-%m-%d %H:%M:%S")
    if ticks <= 0:
        return f"{base}Z"
    fraction = f"{ticks:07d}".rstrip("0")
    return f"{base}.{fraction}Z"


def _new_id() -> str:
    import uuid

    return str(uuid.uuid4())
