"""Telemetry requirements and demo-environment availability (Data Source Mapper, Gap Prioritization).

Copied from the installed app.py: ``normalize_data_source_status``,
``split_data_sources``, ``normalize_ds_token``, ``find_matching_inventory``,
``calculate_feasibility`` and ``inventory_status_summary``.

Changed on purpose: ``data_source_matches`` now compares the normalized
required name with the inventory name and its aliases for equality only. The
installed version also accepted substrings and log types, so "Windows Sysmon
EID 1" matched "Windows Sysmon EID 10" and "EDR Process Access" matched any
source whose log type was "Process Access".

New: ``rule_requirements`` maps a rule's Sigma log source to event types and
checks each detection field against what the demo environment collects.
"""
from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from .sigma_meta import extract_sigma_required_fields

DATA_SOURCE_STATUSES = ("Available", "Partial", "Missing", "Unknown", "Not Applicable")
FEASIBILITY_ORDER = ("High", "Medium", "Low", "Not Possible", "Needs Mapping")
READINESS_LABELS = {
    "ready": "Ready: every detection field is collected",
    "partial": "Partial: some detection fields are not collected",
    "unavailable": "Not available in the demo environment",
    "unmapped": "No event mapping for this log source",
}
FIELD_STATE_LABELS = {
    "collected": "Collected",
    "not_collected": "Not collected in the demo environment",
    "not_in_event": "Not provided by this event type",
}


def normalize_data_source_status(value: Any) -> str:
    raw = str(value or "Unknown").strip().lower().replace("_", " ").replace("-", " ")
    mapping = {
        "available": "Available",
        "enabled": "Available",
        "yes": "Available",
        "partial": "Partial",
        "partially available": "Partial",
        "missing": "Missing",
        "not available": "Missing",
        "no": "Missing",
        "unknown": "Unknown",
        "n/a": "Not Applicable",
        "na": "Not Applicable",
        "not applicable": "Not Applicable",
    }
    return mapping.get(raw, "Unknown")


def split_data_sources(value: Any) -> List[str]:
    if isinstance(value, list):
        items: List[str] = []
        for item in value:
            items.extend(split_data_sources(item))
        return items
    text = str(value or "").strip()
    if not text:
        return []
    parts = re.split(r"[;|,\n]+", text)
    return [p.strip() for p in parts if p.strip()]


def normalize_ds_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def data_source_matches(required: str, inventory_item: Dict[str, Any]) -> bool:
    """Exact match of the normalized name against the inventory name or one of its aliases."""
    required_norm = normalize_ds_token(required)
    if not required_norm:
        return False
    names = [inventory_item.get("data_source", "")] + split_data_sources(inventory_item.get("aliases", ""))
    return any(required_norm == normalize_ds_token(name) for name in names if name)


def find_matching_inventory(required: str, inventory: List[Dict[str, Any]],
                            memo: Optional[Dict[str, Any]] = None
                            ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    if memo is not None:
        if required not in memo:
            memo[required] = find_matching_inventory(required, inventory)
        return memo[required]
    available, partial, other = [], [], []
    for item in inventory:
        if not data_source_matches(required, item):
            continue
        status = normalize_data_source_status(item.get("status"))
        if status == "Available":
            available.append(item)
        elif status == "Partial":
            partial.append(item)
        else:
            other.append(item)
    return available, partial, other


def calculate_feasibility(mapping: Dict[str, Any], inventory: List[Dict[str, Any]],
                          memo: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    required = mapping.get("required", []) or []
    minimum = mapping.get("minimum", []) or required[:1]
    if not required:
        return {
            "feasibility": "Unknown",
            "available_sources": [],
            "partial_sources": [],
            "missing_sources": [],
            "recommended_action": "Create or update the technique-to-data-source mapping before making an engineering decision.",
        }

    available_sources: Set[str] = set()
    partial_sources: Set[str] = set()
    missing_sources: List[str] = []
    minimum_satisfied = True
    all_required_satisfied = True

    for req in required:
        available, partial, other = find_matching_inventory(req, inventory, memo)
        if available:
            available_sources.add(req)
        elif partial:
            partial_sources.add(req)
            all_required_satisfied = False
        else:
            all_required_satisfied = False
            missing_sources.append(req)

    for req in minimum:
        available, partial, other = find_matching_inventory(req, inventory, memo)
        if not available and not partial:
            minimum_satisfied = False
            break

    if all_required_satisfied and required:
        feasibility = "High"
        action = "Enough telemetry exists to start rule engineering. Review rule examples and write/tune the SIEM detection."
    elif minimum_satisfied and (available_sources or partial_sources):
        feasibility = "Medium"
        action = "Core telemetry exists, but some preferred data sources are missing or partial. Write a rule with tuning notes and request missing enrichment."
    elif available_sources or partial_sources:
        feasibility = "Low"
        action = "Only indirect or incomplete telemetry exists. Create a log source request before relying on this detection."
    else:
        feasibility = "Not Possible"
        action = "Required telemetry is not available. Onboard the missing log sources before creating a production SIEM rule."

    return {
        "feasibility": feasibility,
        "available_sources": sorted(available_sources),
        "partial_sources": sorted(partial_sources),
        "missing_sources": missing_sources,
        "recommended_action": action,
    }


def inventory_status_summary(inventory: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {status: 0 for status in DATA_SOURCE_STATUSES}
    for item in inventory:
        summary[normalize_data_source_status(item.get("status"))] += 1
    return summary


# ------------------------------------------------------------------------------ demo-environment data
def load_inventory(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    return [{"data_source": row["name"], "aliases": row["aliases"], "category": row["category"],
             "platform": row["platform"], "status": row["status"],
             "collected_fields": json.loads(row["collected_fields"] or "[]"), "notes": row["notes"]}
            for row in conn.execute("SELECT * FROM data_sources ORDER BY category, name")]


def load_requirement(conn: sqlite3.Connection, technique: str) -> Optional[Dict[str, Any]]:
    row = conn.execute("SELECT * FROM technique_requirements WHERE technique = ?", (technique,)).fetchone()
    if row is None:
        return None
    return {"technique": row["technique"], "required": json.loads(row["required"]),
            "minimum": json.loads(row["minimum"]), "preferred": json.loads(row["preferred"]),
            "guidance": row["guidance"]}


def technique_feasibility(conn: sqlite3.Connection, technique: str,
                          inventory: Optional[List[Dict[str, Any]]] = None,
                          memo: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Technique-level guidance: the curated requirements checked against the demo inventory."""
    mapping = load_requirement(conn, technique)
    if mapping is None:
        return {"technique": technique, "mapped": False, "feasibility": "Needs Mapping", "mapping": None,
                "available_sources": [], "partial_sources": [], "missing_sources": [],
                "recommended_action": "No telemetry guidance is recorded for this technique yet. "
                                      "Use the selected rule's log source to judge the telemetry it needs."}
    result = calculate_feasibility(mapping, inventory if inventory is not None else load_inventory(conn), memo)
    return {"technique": technique, "mapped": True, "mapping": mapping, **result}


def telemetry_summary_text(result: Dict[str, Any]) -> str:
    """Short one-line explanation used in Gap Prioritization reasons."""
    level = result["feasibility"]
    if not result.get("mapped"):
        return "Telemetry: no guidance recorded for this technique (needs mapping)."
    parts = [f"Telemetry guidance for {result['technique']}: {level}"]
    if result["missing_sources"]:
        parts.append("missing " + ", ".join(result["missing_sources"]))
    if result["partial_sources"]:
        parts.append("partial " + ", ".join(result["partial_sources"]))
    return "; ".join(parts) + "."


def _event_types_for(conn: sqlite3.Connection, logsource: Dict[str, str]) -> List[sqlite3.Row]:
    """Event types for a Sigma log source. A mapping row with an empty service applies to any service."""
    return conn.execute(
        """SELECT m.event_type, m.preference, m.field_map, e.label, e.channel, e.event_id, e.fields, e.data_source
           FROM logsource_event_map m JOIN event_types e ON e.key = m.event_type
           WHERE m.product = ? AND m.category = ? AND (m.service = '' OR m.service = ?)
           ORDER BY m.preference, e.key""",
        (logsource["product"], logsource["category"], logsource["service"])).fetchall()


def rule_requirements(conn: sqlite3.Connection, rule: Dict[str, Any], rule_data: Dict[str, Any],
                      inventory: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Event types and fields a rule needs, and which of them the demo environment collects."""
    inventory = inventory if inventory is not None else load_inventory(conn)
    by_name = {item["data_source"]: item for item in inventory}
    fields = extract_sigma_required_fields(rule_data)
    event_types = []
    for row in _event_types_for(conn, rule["logsource"]):
        field_map = json.loads(row["field_map"] or "{}")
        source = by_name.get(row["data_source"], {})
        status = normalize_data_source_status(source.get("status"))
        collected = set(source.get("collected_fields", [])) if status in ("Available", "Partial") else set()
        field_rows = []
        for sigma_field in fields:
            event_field = field_map.get(sigma_field)
            if not event_field:
                state = "not_in_event"
            elif event_field in collected:
                state = "collected"
            else:
                state = "not_collected"
            field_rows.append({"sigma_field": sigma_field, "event_field": event_field or "",
                               "state": state, "state_label": FIELD_STATE_LABELS[state]})
        collected_count = sum(1 for f in field_rows if f["state"] == "collected")
        if status not in ("Available", "Partial") or (fields and collected_count == 0):
            readiness = "unavailable"
        elif collected_count == len(field_rows):
            readiness = "ready"
        else:
            readiness = "partial"
        event_types.append({
            "key": row["event_type"], "label": row["label"], "channel": row["channel"], "event_id": row["event_id"],
            "data_source": row["data_source"], "status": status, "notes": source.get("notes", ""),
            "fields": field_rows, "collected_count": collected_count, "readiness": readiness,
            "readiness_label": READINESS_LABELS[readiness],
        })
    if not event_types:
        overall = "unmapped"
    else:
        overall = min((e["readiness"] for e in event_types), key=("ready", "partial", "unavailable").index)
    best = next((e for e in event_types if e["readiness"] == overall), None)
    return {"fields": fields, "event_types": event_types, "readiness": overall,
            "readiness_label": READINESS_LABELS[overall], "best_event_type": best}


def telemetry_lines(requirements: Dict[str, Any]) -> str:
    """Plain-text telemetry requirements for a Rule Plan, one event type per line."""
    lines = []
    for event in requirements.get("event_types", []):
        wanted = [f["event_field"] or f["sigma_field"] for f in event["fields"] if f["state"] != "not_in_event"]
        state = {"ready": "available in demo", "partial": "partly available in demo",
                 "unavailable": "not available in demo"}[event["readiness"]]
        lines.append(f"{event['data_source']} ({event['label']}): {', '.join(wanted) or 'no mapped fields'} - {state}")
    return "\n".join(lines)
