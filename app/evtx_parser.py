"""EVTX parser for Event-Analyzer.

Backend: evtx (Rust-based, pyevtx-rs).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, Optional
from uuid import uuid4
import ipaddress as _ipaddress

from app.config import get_config
from app.logger import get_logger

logger = get_logger("evtx_parser")


try:
    from evtx import PyEvtxParser as _RustPyEvtxParser
except ImportError:
    try:
        from evtx._native import PyEvtxParser as _RustPyEvtxParser
    except ImportError as exc:
        raise ImportError("Rust EVTX backend required. Install 'evtx' (pyevtx-rs).") from exc

PyEvtxParser = _RustPyEvtxParser
_BACKEND = "rust"
logger.info("EVTX backend: Rust (pyevtx-rs)")


_SYSMON_SPECIFIC_EIDS: set = {
    1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 25
}
_POWERSHELL_SPECIFIC_EIDS: set = {400, 403, 800, 4103, 4104}

EVENT_CATEGORIES = {
    4624: "logon",
    4625: "logon_failed",
    4634: "logoff",
    4647: "logoff",
    4648: "explicit_logon",
    4672: "special_privileges",
    4720: "account_created",
    4722: "account_enabled",
    4723: "password_change",
    4724: "password_reset",
    4725: "account_disabled",
    4726: "account_deleted",
    4728: "group_member_added",
    4732: "group_member_added",
    4733: "group_member_removed",
    4756: "group_member_added",
    4688: "process_created",
    4689: "process_terminated",
    4663: "object_access",
    4656: "handle_requested",
    4719: "audit_policy_changed",
    4739: "domain_policy_changed",
    4697: "service_installed",
    4768: "kerberos_tgt",
    4769: "kerberos_service_ticket",
    4771: "kerberos_preauth_failed",
    4776: "ntlm_authentication",
    4778: "session_reconnected",
    4779: "session_disconnected",
    4698: "scheduled_task_created",
    4699: "scheduled_task_deleted",
    4700: "scheduled_task_enabled",
    4701: "scheduled_task_disabled",
    4702: "scheduled_task_updated",
    7034: "service_crashed",
    7036: "service_state_change",
    7040: "service_start_type_changed",
    7045: "service_installed",
    1: "process_created",
    2: "file_creation_time_changed",
    3: "network_connection",
    5: "process_terminated",
    6: "driver_loaded",
    7: "image_loaded",
    8: "create_remote_thread",
    9: "raw_access_read",
    10: "process_access",
    11: "file_created",
    12: "registry_added_deleted",
    13: "registry_value_set",
    14: "registry_renamed",
    15: "file_stream_created",
    17: "pipe_created",
    18: "pipe_connected",
    19: "wmi_subscription",
    20: "wmi_consumer",
    21: "wmi_binding",
    22: "dns_query",
    23: "file_delete",
    25: "process_tamper",
    4104: "powershell_scriptblock",
    4103: "powershell_module_logging",
    400: "powershell_engine_start",
    403: "powershell_engine_stop",
    800: "powershell_pipeline_execution",
}

LOGON_TYPES = {
    2: "Interactive (console)",
    3: "Network (SMB/mapped drive)",
    4: "Batch (scheduled task)",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials (RunAs)",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}


def parse_evtx_file(
    file_path: str,
    investigation_id: str,
    max_events: int = 0,
) -> Generator[Dict[str, Any], None, None]:
    """Parse an EVTX file and yield structured event dictionaries."""
    from collections import deque

    cfg = get_config()
    store_raw = bool(cfg.store_raw)
    forensic_mode = False

    _recent_procs = deque()
    _recent_proc_times: Dict[tuple, float] = {}
    _MAX_RECENT_PROCS = 500
    _DEDUP_WINDOW_SECONDS = 2.0

    def _parse_ts_epoch(ts: str) -> Optional[float]:
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            return None

    def _dedup_wrapper(generator):
        for event in generator:
            if not event:
                continue
            eid = event.get("event_id")
            if not forensic_mode and eid in (1, 4688):
                comp = event.get("computer", "").lower()
                cmd = event.get("command_line", "").lower()
                proc = event.get("process_name", "").lower()
                ts_epoch = _parse_ts_epoch(event.get("timestamp", ""))
                if comp and proc and cmd and ts_epoch is not None:
                    sig = (comp, proc, cmd)
                    last_ts = _recent_proc_times.get(sig)
                    if last_ts is not None and abs(ts_epoch - last_ts) <= _DEDUP_WINDOW_SECONDS:
                        continue
                    _recent_proc_times[sig] = ts_epoch
                    _recent_procs.append((sig, ts_epoch))
                    if len(_recent_procs) > _MAX_RECENT_PROCS:
                        old_sig, old_ts = _recent_procs.popleft()
                        if _recent_proc_times.get(old_sig) == old_ts:
                            _recent_proc_times.pop(old_sig, None)

            yield event

    if _BACKEND != "rust":
        logger.error("Rust EVTX backend required. Install 'evtx' (pyevtx-rs).")
        return
    yield from _dedup_wrapper(_parse_rust(file_path, investigation_id, max_events))


def _parse_rust(
    file_path: str,
    investigation_id: str,
    max_events: int = 0,
) -> Generator[Dict[str, Any], None, None]:
    """Parse EVTX using the Rust-based evtx parser."""
    file_path = Path(file_path)
    if not file_path.exists():
        logger.error(f"EVTX file not found: {file_path}")
        return

    logger.info(f"Parsing EVTX file: {file_path.name}")
    count = 0
    errors = 0

    try:
        source_file = str(file_path.resolve())
        parser = PyEvtxParser(str(file_path))
        for record in parser.records_json():
            if max_events > 0 and count >= max_events:
                break
            try:
                data = json.loads(record["data"])
                event = _parse_json_event(
                    data,
                    investigation_id,
                    record["data"],
                    source_file=source_file,
                    event_record_id=record.get("event_record_id") or record.get("record_id"),
                )
                if event:
                    if not event.get("timestamp"):
                        errors += 1
                        continue
                    count += 1
                    yield event
            except Exception as exc:
                errors += 1
                if errors <= 10:
                    logger.debug(f"Error parsing JSON record: {exc}")
    except Exception as exc:
        logger.error(f"Failed to open EVTX file {file_path}: {exc}")
        return

    logger.info(f"Parsed {count} events from {file_path.name} ({errors} errors)")


def _get_attr(obj: Any, key: str, default: str = "") -> Any:
    if not isinstance(obj, dict):
        return default
    if key in obj:
        return obj[key]
    attrs = obj.get("#attributes", {})
    if isinstance(attrs, dict) and key in attrs:
        return attrs[key]
    return default


def _parse_json_event(
    data: Dict[str, Any],
    investigation_id: str,
    raw_json: str,
    source_file: str = "",
    event_record_id: Any = None,
) -> Optional[Dict[str, Any]]:
    evt = data.get("Event", data)
    system = evt.get("System")
    if not system or not isinstance(system, dict):
        return None

    event: Dict[str, Any] = {
        "id": str(uuid4()),
        "investigation_id": investigation_id,
        "raw_data": raw_json,
        "source_file": source_file,
        "event_record_id": event_record_id,
    }

    provider_info = system.get("Provider", {})
    event["provider"] = _get_attr(provider_info, "Name", "")

    event["channel"] = system.get("Channel") or _determine_channel(event["provider"])

    eid_raw = system.get("EventID")
    if isinstance(eid_raw, dict):
        eid_raw = eid_raw.get("#text", eid_raw.get("value"))
    try:
        event["event_id"] = int(eid_raw)
    except (ValueError, TypeError):
        pass

    time_info = system.get("TimeCreated", {})
    event["timestamp"] = _get_attr(time_info, "SystemTime", "")

    event["level"] = _safe_int(system.get("Level"))
    event["task"] = str(system.get("Task") or "") or None
    event["opcode"] = str(system.get("Opcode") or "") or None
    event["keywords"] = str(system.get("Keywords") or "") or None

    comp = system.get("Computer", "")
    event["computer"] = comp
    event["hostname"] = comp

    eid = event.get("event_id")
    provider_name = event.get("provider", "").lower()

    if "sysmon" in provider_name:
        event["event_category"] = EVENT_CATEGORIES.get(eid, f"sysmon_{eid}")
    elif "powershell" in provider_name:
        event["event_category"] = EVENT_CATEGORIES.get(eid, f"powershell_{eid}")
    else:
        channel = event.get("channel", "")
        chan_prefix = channel.lower().replace(" ", "_").replace("/", "_") if channel else "event"
        if eid in _SYSMON_SPECIFIC_EIDS or eid in _POWERSHELL_SPECIFIC_EIDS:
            event["event_category"] = f"{chan_prefix}_{eid}"
        else:
            default_cat = f"{chan_prefix}_{eid}" if channel else f"event_{eid}"
            event["event_category"] = EVENT_CATEGORIES.get(eid, default_cat)

    event_data = evt.get("EventData")
    if event_data is None:
        event_data = evt.get("UserData")
        if isinstance(event_data, dict) and len(event_data) == 1:
            inner = next(iter(event_data.values()))
            if isinstance(inner, dict):
                event_data = inner

    if event_data and isinstance(event_data, dict):
        flat_data = _flatten_event_data(event_data)
        _enrich_event(event, flat_data, eid, provider_name)

    event["description"] = _generate_description(event)

    return event


def _flatten_event_data(event_data: Dict[str, Any]) -> Dict[str, str]:
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
                for k, v in value.items():
                    if k != "#attributes" and v is not None:
                        flat[k] = str(v)
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
def _determine_channel(provider_name: str) -> str:
    pn = provider_name.lower()
    if "sysmon" in pn:
        return "Microsoft-Windows-Sysmon/Operational"
    if "powershell" in pn:
        return "Microsoft-Windows-PowerShell/Operational"
    if "security" in pn:
        return "Security"
    if "system" in pn:
        return "System"
    return "Other"


def _enrich_event(event: Dict[str, Any], data: Dict[str, str], event_id: Optional[int], provider: str) -> None:
    provider = provider.lower()

    event["user_name"] = (
        data.get("TargetUserName")
        or data.get("SubjectUserName")
        or data.get("User")
        or data.get("UserName")
        or data.get("AccountName")
    )
    event["user_domain"] = (
        data.get("TargetDomainName")
        or data.get("SubjectDomainName")
        or data.get("Domain")
    )

    if not event_id:
        return

    if event_id in (4624, 4625):
        event["target_user"] = data.get("TargetUserName")
        event["target_domain"] = data.get("TargetDomainName")
        event["source_ip"] = data.get("IpAddress")
        event["source_port"] = _safe_int(data.get("IpPort"))
        event["logon_type"] = _safe_int(data.get("LogonType"))
        event["logon_process"] = data.get("LogonProcessName")
        event["auth_package"] = data.get("AuthenticationPackageName")
        event["impersonation_level"] = data.get("ImpersonationLevel")
        event["target_user_sid"] = data.get("TargetUserSid")
        if event_id == 4624:
            event["user_name"] = data.get("TargetUserName")
            event["user_domain"] = data.get("TargetDomainName")
        elif event_id == 4625:
            event["status_code"] = data.get("SubStatus") or data.get("Status")

    elif event_id == 4688:
        event["process_name"] = data.get("NewProcessName")
        event["process_id"] = _safe_int(data.get("NewProcessId"))
        event["parent_process"] = data.get("ParentProcessName")
        event["command_line"] = data.get("CommandLine")
        event["user_name"] = data.get("SubjectUserName")

    elif event_id in (4720, 4722, 4725, 4726):
        event["target_user"] = data.get("TargetUserName")
        event["target_domain"] = data.get("TargetDomainName")
        event["user_name"] = data.get("SubjectUserName")

    elif event_id in (4728, 4732, 4756):
        event["target_user"] = data.get("MemberName") or data.get("MemberSid")
        event["user_name"] = data.get("SubjectUserName")

    elif event_id in (7045, 4697):
        event["service_name"] = data.get("ServiceName")
        event["file_path"] = data.get("ImagePath") or data.get("ServiceFileName")

    elif event_id in (4698, 4699, 4700, 4701, 4702):
        event["service_name"] = data.get("TaskName")

    elif event_id in (4768, 4769, 4771):
        event["target_user"] = data.get("TargetUserName")
        event["source_ip"] = data.get("IpAddress")
        event["service_name"] = data.get("ServiceName")
        event["status_code"] = (
            data.get("Status")
            or data.get("FailureCode")
            or data.get("FailureReason")
            or data.get("SubStatus")
        )
        event["ticket_options"] = data.get("TicketOptions")
        event["ticket_encryption_type"] = data.get("TicketEncryptionType")
        if event_id == 4768:
            event["pre_auth_type"] = data.get("PreAuthType") or data.get("PreauthType")

    elif event_id == 4662:
        event["object_name"] = data.get("ObjectName")
        event["object_type"] = data.get("ObjectType")
        event["properties"] = data.get("Properties")
        event["access_mask"] = data.get("AccessMask") or data.get("AccessList")

    elif event_id in (4663, 4656):
        event["object_name"] = data.get("ObjectName")
        event["object_type"] = data.get("ObjectType")
        event["process_name"] = data.get("ProcessName")
        event["access_mask"] = data.get("AccessMask") or data.get("AccessList")

    elif event_id == 5145:
        event["share_name"] = data.get("ShareName")
        event["file_path"] = data.get("RelativeTargetName")
        event["process_name"] = data.get("ProcessName")

    elif event_id == 7036:
        event["service_name"] = data.get("param1")
        event["command_line"] = data.get("param2")

    elif event_id in (1000, 1001):
        event["process_name"] = data.get("AppName") or data.get("Appname")
        event["status_code"] = data.get("ExceptionCode")

    if "sysmon" in provider:
        if event_id == 1:
            event["process_name"] = data.get("Image")
            event["process_id"] = _safe_int(data.get("ProcessId"))
            event["parent_process"] = data.get("ParentImage")
            event["command_line"] = data.get("CommandLine")
            event["user_name"] = data.get("User")
            event["hash_value"] = data.get("Hashes")
            event["file_path"] = data.get("CurrentDirectory")
            event["process_guid"] = data.get("ProcessGuid")
            event["parent_process_guid"] = data.get("ParentProcessGuid")
            event["parent_command_line"] = data.get("ParentCommandLine")
            event["original_filename"] = data.get("OriginalFileName")

        elif event_id == 3:
            event["process_name"] = data.get("Image")
            event["source_ip"] = data.get("SourceIp")
            event["dest_ip"] = data.get("DestinationIp")
            event["dest_hostname"] = data.get("DestinationHostname")
            event["source_port"] = _safe_int(data.get("SourcePort"))
            event["dest_port"] = _safe_int(data.get("DestinationPort"))
            event["user_name"] = data.get("User")

        elif event_id == 7:
            event["process_name"] = data.get("Image")
            event["file_path"] = data.get("ImageLoaded")
            event["hash_value"] = data.get("Hashes")

        elif event_id == 10:
            event["process_name"] = data.get("SourceImage")
            event["target_process"] = data.get("TargetImage")
            event["access_mask"] = data.get("GrantedAccess")

        elif event_id == 11:
            event["process_name"] = data.get("Image")
            event["file_path"] = data.get("TargetFilename")

        elif event_id in (12, 13, 14):
            event["process_name"] = data.get("Image")
            event["registry_key"] = data.get("TargetObject")
            event["registry_value"] = data.get("Details")

        elif event_id == 22:
            event["process_name"] = data.get("Image")
            event["query_name"] = data.get("QueryName")
            query_results = data.get("QueryResults")
            if query_results:
                first_result = query_results.split(";")[0].strip()
                try:
                    _ipaddress.ip_address(first_result)
                    event["dest_ip"] = first_result
                except ValueError:
                    pass

        elif event_id == 8:
            event["process_name"] = data.get("SourceImage")
            event["target_process"] = data.get("TargetImage")

        elif event_id == 6:
            event["process_name"] = data.get("Image")
            event["file_path"] = data.get("ImageLoaded")
            event["hash_value"] = data.get("Hashes")

        elif event_id == 9:
            event["process_name"] = data.get("Image")
            event["file_path"] = data.get("Device")

        elif event_id == 15:
            event["process_name"] = data.get("Image")
            event["file_path"] = data.get("TargetFilename")
            event["hash_value"] = data.get("Hash")

        elif event_id in (17, 18):
            event["process_name"] = data.get("Image")
            event["command_line"] = data.get("PipeName")

        elif event_id in (19, 20, 21):
            event["process_name"] = data.get("Image")
            event["service_name"] = (
                data.get("Name") or data.get("Consumer") or data.get("Filter")
            )
            event["command_line"] = " ".join(
                filter(
                    None,
                    [
                        data.get("Type", ""),
                        data.get("Destination", ""),
                        data.get("Consumer", ""),
                        data.get("Filter", ""),
                    ],
                )
            )

        elif event_id == 25:
            event["process_name"] = data.get("Image")
            event["command_line"] = data.get("Type", "")

    if "powershell" in provider:
        if event_id in (400, 403, 800):
            engine_state = data.get("_data_0")
            prev_state = data.get("_data_1")
            details_blob = data.get("_data_2")
            details = _parse_kv_blob(details_blob)
            command_line = details.get("CommandLine") or details.get("HostApplication")
            if command_line and not event.get("command_line"):
                event["command_line"] = command_line
            host_app = details.get("HostApplication")
            if host_app and not event.get("process_name"):
                event["process_name"] = host_app.split()[0]
            if engine_state:
                event["powershell_engine_state"] = engine_state
            if prev_state:
                event["powershell_previous_state"] = prev_state
        if event_id == 4104:
            event["command_line"] = data.get("ScriptBlockText")
            event["file_path"] = data.get("Path")
            event["script_block_id"] = data.get("ScriptBlockId")
            event["script_block_num"] = _safe_int(data.get("MessageNumber"))
            event["script_block_total"] = _safe_int(data.get("MessageTotal"))

    if any(kw in provider for kw in ("windows defender", "microsoft-antimalware", "windefend")):
        if not event.get("file_path"):
            event["file_path"] = data.get("Path")
        if not event.get("process_name"):
            event["process_name"] = data.get("ProcessName")

    if "codeintegrity" in provider:
        if not event.get("file_path"):
            event["file_path"] = data.get("FileNameBuffer")
        if not event.get("process_name"):
            event["process_name"] = data.get("ProcessNameBuffer")

    if "appxdeployment" in provider or "appxpackaging" in provider:
        if not event.get("file_path"):
            event["file_path"] = data.get("Path")

    if event_id == 4648:
        event["target_user"] = data.get("TargetUserName")
        event["target_domain"] = data.get("TargetDomainName") or data.get("TargetServerName")
        event["source_ip"] = data.get("IpAddress")


def _safe_int(val) -> Optional[int]:
    if val is None:
        return None
    if isinstance(val, int):
        return val
    try:
        val = str(val)
        if val.startswith("0x"):
            return int(val, 16)
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_kv_blob(blob: Optional[str]) -> Dict[str, str]:
    if not blob:
        return {}
    text = str(blob)
    keys = [
        "NewEngineState",
        "PreviousEngineState",
        "SequenceNumber",
        "HostName",
        "HostVersion",
        "HostId",
        "HostApplication",
        "EngineVersion",
        "RunspaceId",
        "PipelineId",
        "CommandName",
        "CommandType",
        "ScriptName",
        "CommandPath",
        "CommandLine",
    ]
    positions = []
    for key in keys:
        marker = f"{key}="
        idx = text.find(marker)
        if idx != -1:
            positions.append((idx, key))
    if not positions:
        return {}
    positions.sort()
    result: Dict[str, str] = {}
    for i, (idx, key) in enumerate(positions):
        start = idx + len(key) + 1
        end = positions[i + 1][0] if i + 1 < len(positions) else len(text)
        value = " ".join(text[start:end].strip().split())
        result[key] = value
    return result


def _generate_description(event: Dict[str, Any]) -> str:
    eid = event.get("event_id")
    cat = event.get("event_category", "")

    if eid == 4624:
        logon_desc = LOGON_TYPES.get(event.get("logon_type", 0), "Unknown")
        user = event.get("target_user") or event.get("user_name") or "Unknown"
        src = event.get("source_ip") or "local"
        return f"Successful logon: {user} via {logon_desc} from {src}"

    if eid == 4625:
        user = event.get("target_user") or event.get("user_name") or "Unknown"
        src = event.get("source_ip") or "local"
        return f"Failed logon attempt: {user} from {src}"

    if eid == 4688:
        proc = event.get("process_name") or "Unknown"
        user = event.get("user_name") or "Unknown"
        return f"Process created: {proc} by {user}"

    if eid == 4720:
        target = event.get("target_user") or "Unknown"
        by = event.get("user_name") or "Unknown"
        return f"Account created: {target} by {by}"

    if eid == 4732:
        target = event.get("target_user") or "Unknown"
        by = event.get("user_name") or "Unknown"
        return f"User added to privileged group by {by}: {target}"

    if eid in (7045, 4697):
        svc = event.get("service_name") or "Unknown"
        path = event.get("file_path") or ""
        return f"Service installed: {svc} ({path})"

    if cat == "process_created" and "sysmon" in event.get("provider", "").lower():
        proc = event.get("process_name") or "Unknown"
        cmd = event.get("command_line") or ""
        parent = event.get("parent_process") or ""
        if len(cmd) > 100:
            cmd = cmd[:100] + "..."
        return f"Process: {proc} (Parent: {parent}) Cmd: {cmd}"

    if cat == "network_connection":
        proc = event.get("process_name") or "Unknown"
        dst = event.get("dest_ip") or "Unknown"
        port = event.get("dest_port") or ""
        return f"Network connection: {proc} -> {dst}:{port}"

    if cat == "file_created":
        proc = event.get("process_name") or "Unknown"
        fp = event.get("file_path") or "Unknown"
        return f"File created: {fp} by {proc}"

    if cat in ("registry_value_set", "registry_added_deleted"):
        proc = event.get("process_name") or "Unknown"
        key = event.get("registry_key") or "Unknown"
        return f"Registry modified: {key} by {proc}"

    if cat == "process_access":
        src = event.get("process_name") or "Unknown"
        tgt = event.get("target_process") or event.get("target_user") or "Unknown"
        return f"Process access: {src} accessed {tgt}"

    if cat == "powershell_scriptblock":
        cmd = event.get("command_line") or ""
        if len(cmd) > 500:
            cmd = cmd[:500] + "..."
        return f"PowerShell script block: {cmd}"

    if cat == "dns_query":
        proc = event.get("process_name") or "Unknown"
        query = event.get("query_name") or event.get("dest_ip") or "Unknown"
        return f"DNS query: {query} by {proc}"

    if eid == 4672:
        user = event.get("user_name") or "Unknown"
        return f"Special privileges assigned to: {user}"

    if eid in (4698, 4699):
        task = event.get("service_name") or "Unknown"
        action = "created" if eid == 4698 else "deleted"
        return f"Scheduled task {action}: {task}"

    if eid == 4648:
        user = event.get("user_name") or "Unknown"
        target = event.get("target_user") or "Unknown"
        target_domain = event.get("target_domain") or ""
        return f"Explicit credential logon: {user} -> {target_domain}\\{target}"

    if eid == 4719:
        return f"System audit policy was changed by {event.get('user_name') or 'Unknown'}"

    if eid == 4725:
        target = event.get("target_user") or "Unknown"
        by = event.get("user_name") or "Unknown"
        return f"Account disabled: {target} by {by}"

    if eid == 4726:
        target = event.get("target_user") or "Unknown"
        by = event.get("user_name") or "Unknown"
        return f"Account deleted: {target} by {by}"

    if eid == 4728:
        target = event.get("target_user") or "Unknown"
        by = event.get("user_name") or "Unknown"
        return f"Member added to security-enabled global group by {by}: {target}"

    if eid == 4756:
        target = event.get("target_user") or "Unknown"
        by = event.get("user_name") or "Unknown"
        return f"Member added to security-enabled universal group by {by}: {target}"

    if eid == 4768:
        user = event.get("target_user") or event.get("user_name") or "Unknown"
        src = event.get("source_ip") or "local"
        return f"Kerberos TGT requested by {user} from {src}"

    if eid == 4769:
        user = event.get("target_user") or event.get("user_name") or "Unknown"
        svc = event.get("service_name") or "Unknown"
        return f"Kerberos service ticket requested: {user} for {svc}"

    if eid == 4771:
        user = event.get("target_user") or event.get("user_name") or "Unknown"
        src = event.get("source_ip") or "local"
        return f"Kerberos pre-authentication failed: {user} from {src}"

    if eid == 7036:
        svc = event.get("service_name") or "Unknown"
        return f"Service state changed: {svc}"

    if eid == 7040:
        svc = event.get("service_name") or "Unknown"
        return f"Service start type changed: {svc}"

    if cat == "create_remote_thread":
        src = event.get("process_name") or "Unknown"
        tgt = event.get("target_process") or "Unknown"
        return f"Remote thread created: {src} -> {tgt}"

    return f"Event {eid} ({cat})"


def get_file_info(file_path: str) -> Dict[str, Any]:
    fp = Path(file_path)
    info = {
        "name": fp.name,
        "size_bytes": fp.stat().st_size if fp.exists() else 0,
        "size_mb": round(fp.stat().st_size / (1024 * 1024), 2) if fp.exists() else 0,
        "exists": fp.exists(),
    }
    return info
