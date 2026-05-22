"""Validate Rust JSON vs XML parsing for unique event types.

Usage (default root is this test folder):
  python validate_parsing.py --delete-source
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def _load_parser():
    try:
        from evtx import PyEvtxParser as Parser
    except Exception:
        from evtx._native import PyEvtxParser as Parser
    return Parser


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _find_child(parent: ET.Element, tag: str) -> Optional[ET.Element]:
    for child in parent:
        if _strip_ns(child.tag) == tag:
            return child
    return None


def _normalize_value(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    text = " ".join(text.split())
    lower = text.lower()
    if lower in {"true", "false"}:
        return lower
    return text


def _normalize_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    has_data0 = "_data_0" in fields
    for key, value in fields.items():
        new_key = key
        if key in {"Data", "#text"} and not has_data0:
            new_key = "_data_0"
        if new_key in normalized:
            continue
        if _normalize_value(value) == "":
            continue
        normalized[new_key] = value
    return normalized


def _safe_slug(text: str, max_len: int = 80) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", text).strip("_")
    if not slug:
        slug = "unknown"
    if len(slug) > max_len:
        slug = slug[:max_len]
    return slug


def _get_attr(obj: Any, key: str, default: str = "") -> Any:
    if not isinstance(obj, dict):
        return default
    if key in obj:
        return obj[key]
    attrs = obj.get("#attributes", {})
    if isinstance(attrs, dict) and key in attrs:
        return attrs[key]
    return default


def _flatten_event_data_json(event_data: Dict[str, Any]) -> Dict[str, str]:
    flat: Dict[str, str] = {}
    for key, value in event_data.items():
        if key == "#attributes":
            continue
        if isinstance(value, dict):
            if "#text" in value:
                text_val = value["#text"]
                if isinstance(text_val, list):
                    if key == "Data":
                        for i, item in enumerate(text_val):
                            if item is not None:
                                flat[f"_data_{i}"] = str(item)
                    else:
                        for i, item in enumerate(text_val):
                            if item is not None:
                                flat[f"{key}_{i}"] = str(item)
                else:
                    flat[key] = str(text_val)
            else:
                for inner_k, inner_v in value.items():
                    if inner_k != "#attributes" and inner_v is not None:
                        flat[inner_k] = str(inner_v)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    name = item.get("Name", f"_data_{i}")
                    text = item.get("#text", "")
                    flat[name] = str(text) if text is not None else ""
                elif item is not None:
                    flat[f"_data_{i}"] = str(item)
        elif value is not None:
            flat[key] = str(value)
    return flat


def _parse_xml_fields(xml_str: str) -> Dict[str, Any]:
    fields: Dict[str, Any] = {}
    root = ET.fromstring(xml_str)
    system = _find_child(root, "System")
    if system is not None:
        provider_el = _find_child(system, "Provider")
        if provider_el is not None:
            fields["provider"] = provider_el.get("Name", "")
        event_id_el = _find_child(system, "EventID")
        if event_id_el is not None and event_id_el.text:
            fields["event_id"] = event_id_el.text
        time_el = _find_child(system, "TimeCreated")
        if time_el is not None:
            fields["timestamp"] = time_el.get("SystemTime", "")
        record_el = _find_child(system, "EventRecordID")
        if record_el is not None and record_el.text:
            fields["event_record_id"] = record_el.text
        level_el = _find_child(system, "Level")
        if level_el is not None and level_el.text:
            fields["level"] = level_el.text
        task_el = _find_child(system, "Task")
        if task_el is not None and task_el.text:
            fields["task"] = task_el.text
        opcode_el = _find_child(system, "Opcode")
        if opcode_el is not None and opcode_el.text:
            fields["opcode"] = opcode_el.text
        keywords_el = _find_child(system, "Keywords")
        if keywords_el is not None and keywords_el.text:
            fields["keywords"] = keywords_el.text
        channel_el = _find_child(system, "Channel")
        if channel_el is not None and channel_el.text:
            fields["channel"] = channel_el.text
        computer_el = _find_child(system, "Computer")
        if computer_el is not None and computer_el.text:
            fields["computer"] = computer_el.text

    def _parse_event_data(node: ET.Element) -> None:
        data_index = 0
        for child in node:
            tag = _strip_ns(child.tag)
            if tag == "Data":
                name = child.get("Name", "")
                value = child.text or ""
                if name:
                    fields[name] = value
                else:
                    fields[f"_data_{data_index}"] = value
                    data_index += 1
            elif child.text:
                fields[tag] = child.text
            for subchild in child:
                subtag = _strip_ns(subchild.tag)
                if subchild.text:
                    fields[subtag] = subchild.text

    def _is_indexed_tag(name: str) -> bool:
        return bool(re.search(r"_\d+$", name))

    def _parse_user_data(node: ET.Element) -> None:
        for child in node:
            tag = _strip_ns(child.tag)
            if len(child) == 0:
                if child.text:
                    fields[tag] = child.text
                continue
            # If the child has leaf grandchildren, store as a dict (e.g., Process_1, Tag_1)
            if all(len(grand) == 0 for grand in child):
                if _is_indexed_tag(tag):
                    entry = {}
                    for grand in child:
                        gtag = _strip_ns(grand.tag)
                        entry[gtag] = grand.text
                    if entry:
                        fields[tag] = entry
                else:
                    for grand in child:
                        gtag = _strip_ns(grand.tag)
                        if grand.text:
                            fields[gtag] = grand.text
                continue
            _parse_user_data(child)

    event_data = _find_child(root, "EventData")
    if event_data is not None:
        _parse_event_data(event_data)
        return fields

    user_data = _find_child(root, "UserData")
    if user_data is None:
        return fields
    if len(user_data) == 1:
        first = list(user_data)[0]
        if isinstance(first, ET.Element):
            _parse_user_data(first)
            return fields
    _parse_user_data(user_data)

    return fields


def _parse_json_fields_from_data(data: Dict[str, Any]) -> Dict[str, Any]:
    evt = data.get("Event", data)
    fields: Dict[str, Any] = {}
    system = evt.get("System", {}) if isinstance(evt, dict) else {}

    provider_info = system.get("Provider", {})
    fields["provider"] = _get_attr(provider_info, "Name", "")

    channel = system.get("Channel")
    if channel:
        fields["channel"] = channel

    eid_raw = system.get("EventID")
    if isinstance(eid_raw, dict):
        eid_raw = eid_raw.get("#text", eid_raw.get("value"))
    if eid_raw is not None:
        fields["event_id"] = str(eid_raw)

    time_info = system.get("TimeCreated", {})
    fields["timestamp"] = _get_attr(time_info, "SystemTime", "")

    record_id = system.get("EventRecordID")
    if isinstance(record_id, dict):
        record_id = record_id.get("#text", record_id.get("value"))
    if record_id is not None:
        fields["event_record_id"] = str(record_id)

    level = system.get("Level")
    if level is not None:
        fields["level"] = str(level)
    task = system.get("Task")
    if task is not None:
        fields["task"] = str(task)
    opcode = system.get("Opcode")
    if opcode is not None:
        fields["opcode"] = str(opcode)
    keywords = system.get("Keywords")
    if keywords is not None:
        fields["keywords"] = str(keywords)

    computer = system.get("Computer")
    if computer:
        fields["computer"] = computer

    event_data = evt.get("EventData") if isinstance(evt, dict) else None
    if event_data is None:
        event_data = evt.get("UserData") if isinstance(evt, dict) else None
        if isinstance(event_data, dict) and len(event_data) == 1:
            inner = next(iter(event_data.values()))
            if isinstance(inner, dict):
                event_data = inner

    if isinstance(event_data, dict):
        fields.update(_flatten_event_data_json(event_data))

    return fields


def _parse_json_fields(json_str: str) -> Dict[str, Any]:
    return _parse_json_fields_from_data(json.loads(json_str))


def _event_key_from_json(data: Dict[str, Any]) -> Tuple[str, str, str]:
    evt = data.get("Event", data)
    system = evt.get("System", {}) if isinstance(evt, dict) else {}
    provider_info = system.get("Provider", {})
    provider = _get_attr(provider_info, "Name", "")
    channel = system.get("Channel", "")
    eid_raw = system.get("EventID")
    if isinstance(eid_raw, dict):
        eid_raw = eid_raw.get("#text", eid_raw.get("value"))
    event_id = str(eid_raw) if eid_raw is not None else ""
    return event_id.strip() or "unknown", str(provider).strip() or "unknown", str(channel).strip() or "unknown"


def _event_key(fields: Dict[str, Any]) -> Tuple[str, str, str]:
    event_id = str(fields.get("event_id", "")).strip()
    provider = str(fields.get("provider", "")).strip()
    channel = str(fields.get("channel", "")).strip()
    return event_id or "unknown", provider or "unknown", channel or "unknown"


def _diff_fields(xml_fields: Dict[str, Any], json_fields: Dict[str, Any]) -> Dict[str, Any]:
    xml_norm = _normalize_fields(xml_fields)
    json_norm = _normalize_fields(json_fields)
    xml_keys = set(xml_norm.keys())
    json_keys = set(json_norm.keys())
    missing_in_json = sorted(xml_keys - json_keys)
    missing_in_xml = sorted(json_keys - xml_keys)
    value_diffs = {}
    for key in sorted(xml_keys & json_keys):
        left = _normalize_value(xml_norm.get(key))
        right = _normalize_value(json_norm.get(key))
        if left != right:
            value_diffs[key] = {"xml": left, "json": right}
    return {
        "missing_in_json": missing_in_json,
        "missing_in_xml": missing_in_xml,
        "value_diffs": value_diffs,
    }


def _iter_evtx_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.evtx"):
        if path.is_file():
            yield path


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Rust JSON vs XML for unique event types.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--delete-source", action="store_true")
    parser.add_argument("--progress-interval", type=int, default=5000)
    parser.add_argument("--max-records", type=int, default=0)
    parser.add_argument("--from-samples", action="store_true")
    parser.add_argument("--samples-dir", type=Path, default=None)
    args = parser.parse_args()

    root = args.root.resolve()
    output_root = args.output or (root / "validation_output")
    samples_dir = output_root / "unique_samples"
    diffs_dir = output_root / "diffs"
    samples_dir.mkdir(parents=True, exist_ok=True)
    diffs_dir.mkdir(parents=True, exist_ok=True)

    unique = {}
    xml_field_set = set()
    json_field_set = set()
    total_records = 0

    if args.from_samples:
        samples_dir = args.samples_dir or (root / "validation_output" / "unique_samples")
        for sample_path in sorted(samples_dir.glob("*.json")):
            payload = json.loads(sample_path.read_text(encoding="utf-8"))
            key_parts = (
                str(payload.get("event_id", "")),
                str(payload.get("provider", "")),
                str(payload.get("channel", "")),
            )
            key = "|".join(key_parts)
            xml_str = payload.get("xml", "")
            json_str = payload.get("json", "")
            xml_fields = _parse_xml_fields(xml_str) if xml_str else {}
            json_fields = _parse_json_fields(json_str) if json_str else {}
            payload["xml_fields"] = xml_fields
            payload["json_fields"] = json_fields
            unique[key] = payload
            xml_field_set.update(xml_fields.keys())
            json_field_set.update(json_fields.keys())
        total_records = len(unique)
    else:
        Parser = _load_parser()
        for evtx_path in _iter_evtx_files(root):
            print(f"Scanning {evtx_path}...", flush=True)
            parser_xml = Parser(str(evtx_path))
            parser_json = Parser(str(evtx_path))
            records_in_file = 0
            for rec_xml, rec_json in zip(parser_xml.records(), parser_json.records_json()):
                total_records += 1
                records_in_file += 1
                if args.max_records and total_records > args.max_records:
                    break
                xml_str = rec_xml.get("data")
                json_str = rec_json.get("data")
                if not xml_str or not json_str:
                    continue
                try:
                    json_data = json.loads(json_str)
                except Exception:
                    continue

                key_parts = _event_key_from_json(json_data)
                key = "|".join(key_parts)
                if key in unique:
                    continue

                try:
                    xml_fields = _parse_xml_fields(xml_str)
                    json_fields = _parse_json_fields_from_data(json_data)
                except Exception:
                    continue

                xml_field_set.update(xml_fields.keys())
                json_field_set.update(json_fields.keys())

                record_id = rec_json.get("event_record_id") or rec_json.get("record_id")
                unique[key] = {
                    "event_id": key_parts[0],
                    "provider": key_parts[1],
                    "channel": key_parts[2],
                    "source_file": str(evtx_path),
                    "event_record_id": record_id,
                    "xml": xml_str,
                    "json": json_str,
                    "xml_fields": xml_fields,
                    "json_fields": json_fields,
                }

                if args.progress_interval and len(unique) % max(1, args.progress_interval // 5) == 0:
                    print(f"Unique events: {len(unique)} (scanned {total_records})", flush=True)

                if args.progress_interval and records_in_file % args.progress_interval == 0:
                    print(f"  Scanned {records_in_file} records in {evtx_path.name}", flush=True)

            if args.max_records and total_records > args.max_records:
                break

    summary_path = output_root / "summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "key",
            "event_id",
            "provider",
            "channel",
            "source_file",
            "event_record_id",
            "xml_field_count",
            "json_field_count",
            "missing_in_json",
            "missing_in_xml",
            "value_diff_count",
        ])
        for key, payload in sorted(unique.items()):
            diffs = _diff_fields(payload["xml_fields"], payload["json_fields"])
            writer.writerow([
                key,
                payload["event_id"],
                payload["provider"],
                payload["channel"],
                payload["source_file"],
                payload["event_record_id"],
                len(payload["xml_fields"]),
                len(payload["json_fields"]),
                ";".join(diffs["missing_in_json"]),
                ";".join(diffs["missing_in_xml"]),
                len(diffs["value_diffs"]),
            ])

            safe_name = _safe_slug(key)
            key_hash = hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]
            sample_name = f"{safe_name}_{key_hash}.json"
            diff_name = f"{safe_name}_{key_hash}.diff.json"

            sample_path = samples_dir / sample_name
            diff_path = diffs_dir / diff_name

            with sample_path.open("w", encoding="utf-8") as sample_handle:
                json.dump(payload, sample_handle, indent=2, ensure_ascii=True)

            with diff_path.open("w", encoding="utf-8") as diff_handle:
                json.dump(diffs, diff_handle, indent=2, ensure_ascii=True)

    fields_path = output_root / "unique_fields.json"
    with fields_path.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "unique_key": "event_id|provider|channel",
                "xml_fields": sorted(xml_field_set),
                "json_fields": sorted(json_field_set),
                "all_fields": sorted(xml_field_set | json_field_set),
            },
            handle,
            indent=2,
            ensure_ascii=True,
        )

    stats_path = output_root / "stats.json"
    with stats_path.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "total_records_scanned": total_records,
                "unique_events": len(unique),
                "output_root": str(output_root),
            },
            handle,
            indent=2,
            ensure_ascii=True,
        )

    if args.delete_source:
        for folder in ("Benign", "Logs", "Malicious"):
            target = root / folder
            if target.exists() and target.is_dir():
                shutil.rmtree(target)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
