"""Load the bundled demo dataset into a new database (called only by init-db).

Seed files are parsed as data with ``yaml.safe_load`` / ``json.loads``; no
seed value is ever executed. Every rule must carry at least one ATT&CK
technique, matching the installed toolkit, which drops untagged records.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml

from . import attack
from .config import SEED_DIR
from .sigma_meta import content_hash, extract_techniques, logsource_of

RULES_DIR = SEED_DIR / "rules"
RULE_NAMESPACE = "detection-toolkit-demo"
DATA_SOURCE_STATUSES = ("Available", "Partial", "Missing", "Unknown", "Not Applicable")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def rule_uid(source_id: str, file_name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{RULE_NAMESPACE}:{source_id}/{file_name}"))


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _text(value: Any) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return "" if value is None else str(value).strip()


def load_sources(conn: sqlite3.Connection) -> List[str]:
    ids = []
    for item in _json(SEED_DIR / "sources.json"):
        conn.execute("INSERT INTO sources (id, name, license, license_url, homepage, notice) VALUES (?,?,?,?,?,?)",
                     (item["id"], item["name"], item["license"], item.get("license_url", ""),
                      item.get("homepage", ""), item.get("notice", "")))
        ids.append(item["id"])
    if not ids:
        raise ValueError("sources.json must list at least one rule source")
    return ids


def load_rules(conn: sqlite3.Connection, source_id: str) -> Dict[str, str]:
    """Insert every bundled rule; returns {file name: uid}."""
    uids: Dict[str, str] = {}
    files = sorted(RULES_DIR.glob("*.yml"))
    if not files:
        raise ValueError(f"No Sigma rules found in {RULES_DIR}")
    for path in files:
        raw_yaml = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw_yaml)
        if not isinstance(data, dict):
            raise ValueError(f"{path.name}: a Sigma rule must be a YAML mapping")
        missing = [key for key in ("title", "logsource", "detection") if not data.get(key)]
        if missing:
            raise ValueError(f"{path.name}: missing required Sigma field(s): {', '.join(missing)}")
        techniques = sorted(extract_techniques(data))
        if not techniques:
            raise ValueError(f"{path.name}: no ATT&CK technique tag found")
        logsource = logsource_of(data)
        references = data.get("references") if isinstance(data.get("references"), list) else []
        uid = rule_uid(source_id, path.name)
        conn.execute(
            """INSERT INTO rules (uid, source_id, rule_id, title, description, status, level, author, rule_date,
                                  modified, logsource_product, logsource_category, logsource_service, file_path,
                                  reference_url, raw_yaml, content_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, source_id, _text(data.get("id")), _text(data.get("title")), _text(data.get("description")),
             _text(data.get("status")), _text(data.get("level")), _text(data.get("author")), _text(data.get("date")),
             _text(data.get("modified")), logsource["product"], logsource["category"], logsource["service"],
             f"rules/{path.name}", _text(references[0]) if references else "", raw_yaml, content_hash(raw_yaml)))
        conn.executemany("INSERT INTO mitre_index (technique, rule_uid) VALUES (?, ?)",
                         [(technique, uid) for technique in techniques])
        uids[path.name] = uid
    return uids


def load_telemetry(conn: sqlite3.Connection) -> Dict[str, int]:
    data = _json(SEED_DIR / "telemetry.json")
    for item in data["inventory"]:
        if item["status"] not in DATA_SOURCE_STATUSES:
            raise ValueError(f"Unknown data source status {item['status']!r} for {item['data_source']}")
        conn.execute("""INSERT INTO data_sources (name, aliases, category, platform, status, collected_fields, notes)
                        VALUES (?,?,?,?,?,?,?)""",
                     (item["data_source"], item.get("aliases", ""), item.get("category", ""), item.get("platform", ""),
                      item["status"], json.dumps(item.get("collected_fields", [])), item.get("notes", "")))
    for item in data["event_types"]:
        conn.execute("INSERT INTO event_types (key, data_source, label, channel, event_id, fields) VALUES (?,?,?,?,?,?)",
                     (item["key"], item["data_source"], item["label"], item.get("channel", ""), item.get("event_id"),
                      json.dumps(item.get("fields", []))))
    for item in data["logsource_map"]:
        conn.execute("""INSERT INTO logsource_event_map (product, category, service, event_type, preference, field_map)
                        VALUES (?,?,?,?,?,?)""",
                     (item["product"].lower(), item.get("category", "").lower(), item.get("service", "").lower(),
                      item["event_type"], int(item.get("preference", 1)), json.dumps(item.get("field_map", {}))))
    for item in data["technique_requirements"]:
        technique = attack.clean_technique(item["technique"])
        conn.execute("""INSERT INTO technique_requirements (technique, required, minimum, preferred, guidance)
                        VALUES (?,?,?,?,?)""",
                     (technique, json.dumps(item.get("required", [])), json.dumps(item.get("minimum", [])),
                      json.dumps(item.get("preferred", [])), item.get("guidance", "")))
    return {"data_sources": len(data["inventory"]), "event_types": len(data["event_types"]),
            "technique_requirements": len(data["technique_requirements"])}


def load_reports(conn: sqlite3.Connection) -> int:
    data = _json(SEED_DIR / "threat_reports.json")
    for report in data["reports"]:
        conn.execute("INSERT INTO threat_reports (id, name, year, note) VALUES (?,?,?,?)",
                     (report["id"], report["name"], report.get("year"), report.get("note", "")))
        for entry in report["entries"]:
            conn.execute("INSERT INTO threat_report_entries (report_id, rank, technique) VALUES (?,?,?)",
                         (report["id"], int(entry["rank"]), attack.clean_technique(entry["technique"])))
    return len(data["reports"])


def load_demo_events(conn: sqlite3.Connection, uids: Dict[str, str]) -> int:
    data = _json(SEED_DIR / "demo_events.json")
    uid = uids[data["rule_file"]]
    for item in data["events"]:
        conn.execute("""INSERT INTO demo_events (rule_uid, event_type, label, expectation, explanation, event_json)
                        VALUES (?,?,?,?,?,?)""",
                     (uid, data["event_type"], item["label"], item["expectation"], item.get("explanation", ""),
                      json.dumps(item["event"], ensure_ascii=False)))
    return len(data["events"])


def load_plans(conn: sqlite3.Connection, uids: Dict[str, str]) -> int:
    stamp = now_iso()
    plans = _json(SEED_DIR / "plans.json")
    for item in plans:
        uid = uids[item["rule_file"]] if item.get("rule_file") else None
        technique = attack.clean_technique(item["technique"])
        conn.execute(
            """INSERT INTO rule_plan (technique, title, rule_uid, source_key, origin, priority, status,
                                      validation_status, telemetry, validation_notes, notes, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (technique, item["title"], uid, f"rule:{uid}" if uid else f"technique:{technique}", "seed",
             item.get("priority", "Medium"), item["status"], item["validation_status"], item.get("telemetry", ""),
             item.get("validation_notes", ""), item.get("notes", ""), stamp, stamp))
    return len(plans)


def load_all(conn: sqlite3.Connection) -> Dict[str, Any]:
    source_ids = load_sources(conn)
    uids = load_rules(conn, source_ids[0])
    summary: Dict[str, Any] = {"sources": len(source_ids), "rules": len(uids)}
    summary.update(load_telemetry(conn))
    summary["threat_reports"] = load_reports(conn)
    summary["demo_events"] = load_demo_events(conn, uids)
    summary["plans"] = load_plans(conn, uids)
    return summary
