"""Rule plans stored in the edition's own SQLite database.

Kept from the earlier Detection Toolkit: one plan per reservation key, with a
"reopen the existing plan" answer to duplicates, the status and priority
normalizers, the whitelisted update and the validation-state rules. The plan
itself is deliberately small: no users, reviews or deployment tracking.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import attack
from .rules import uid_param

STATUSES = {"planned": "Planned", "in_progress": "In progress", "completed": "Completed", "rejected": "Rejected"}
OPEN_STATUSES = ("planned", "in_progress", "completed")
VALIDATION_STATUSES = {
    "not_assessed": "Not assessed",
    "implementable": "Implementable - telemetry is available",
    "blocked": "Blocked - telemetry or logic is missing",
    "validated": "Lab validated",
}
PRIORITIES = ("High", "Medium", "Low")
ORIGINS = ("manual", "gaps", "rules", "coverage", "data_sources", "converter")
LIMITS = {"title": 200, "telemetry": 4000, "validation_notes": 4000, "notes": 4000}


def now_iso() -> str:
    """UTC timestamp with microseconds, so the edit-conflict check notices quick successive saves."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def source_key(technique: str, rule_uid: Optional[str]) -> str:
    """Reservation key: one plan per selected rule, or one rule-less plan per technique."""
    return f"rule:{rule_uid}" if rule_uid else f"technique:{technique}"


def _clean_text(form: Any, name: str, errors: Dict[str, str]) -> str:
    value = str(form.get(name) or "").replace("\r\n", "\n").strip()
    if len(value) > LIMITS[name]:
        errors[name] = f"Keep this under {LIMITS[name]} characters."
    return value


def validate(conn: sqlite3.Connection, form: Any) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Clean a submitted plan. Returns (values, errors keyed by field name)."""
    errors: Dict[str, str] = {}
    values: Dict[str, Any] = {}
    try:
        values["technique"] = attack.clean_technique(form.get("technique"))
    except ValueError as exc:
        values["technique"] = str(form.get("technique") or "").strip()
        errors["technique"] = str(exc)
    if not values["technique"] and "technique" not in errors:
        errors["technique"] = "Enter the ATT&CK technique this plan covers."
    raw_rule = str(form.get("rule") or "").strip()
    values["rule_uid"] = uid_param(raw_rule)
    rule_row = None
    if raw_rule and not values["rule_uid"]:
        errors["rule"] = "Choose a rule from the list."
    elif values["rule_uid"]:
        rule_row = conn.execute("SELECT uid, title FROM rules WHERE uid = ?", (values["rule_uid"],)).fetchone()
        if rule_row is None:
            errors["rule"] = "That rule is not in the library."
        elif values["technique"] and "technique" not in errors:
            mapped = [r[0] for r in conn.execute("SELECT technique FROM mitre_index WHERE rule_uid = ?",
                                                 (values["rule_uid"],))]
            if values["technique"] not in mapped and attack.family(values["technique"]) not in {attack.family(t) for t in mapped}:
                errors["rule"] = (f"The selected rule maps to {', '.join(mapped)}, not to "
                                      f"{values['technique']} or its family.")
    values["title"] = _clean_text(form, "title", errors)
    if not values["title"] and "technique" not in errors:
        name = attack.technique_name(values["technique"])
        values["title"] = rule_row["title"] if rule_row is not None else (
            f"{values['technique']} {name}".strip() if values["technique"] else "")
    status = str(form.get("status") or "planned").strip()
    values["status"] = status if status in STATUSES else "planned"
    if status not in STATUSES:
        errors["status"] = "Choose a listed status."
    validation = str(form.get("validation_status") or "not_assessed").strip()
    values["validation_status"] = validation if validation in VALIDATION_STATUSES else "not_assessed"
    if validation not in VALIDATION_STATUSES:
        errors["validation_status"] = "Choose a listed validation status."
    priority = str(form.get("priority") or "Medium").strip().capitalize()
    values["priority"] = priority if priority in PRIORITIES else "Medium"
    origin = str(form.get("origin") or "manual").strip()
    values["origin"] = origin if origin in ORIGINS else "manual"
    values["telemetry"] = _clean_text(form, "telemetry", errors)
    values["validation_notes"] = _clean_text(form, "validation_notes", errors)
    values["notes"] = _clean_text(form, "notes", errors)

    # Validation-state rules (reduced from the installed assessment validator).
    state = values["validation_status"]
    if state in ("implementable", "validated") and not values["telemetry"]:
        errors.setdefault("telemetry", "List the telemetry this rule needs before marking it implementable or validated.")
    if state == "blocked" and not values["validation_notes"]:
        errors.setdefault("validation_notes", "Explain what blocks this rule.")
    if state == "validated":
        if not values["rule_uid"]:
            errors.setdefault("rule", "Select the rule that was validated.")
        if not values["validation_notes"]:
            errors.setdefault("validation_notes", "Describe the lab evidence: events, dates and results.")
    return values, errors


def _row(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    item["status_label"] = STATUSES.get(item["status"], item["status"])
    item["validation_label"] = VALIDATION_STATUSES.get(item["validation_status"], item["validation_status"])
    item["technique_name"] = attack.technique_name(item["technique"])
    return item


PLAN_SELECT = "SELECT p.*, r.title AS rule_title FROM rule_plan p LEFT JOIN rules r ON r.uid = p.rule_uid"


def get(conn: sqlite3.Connection, plan_id: int) -> Optional[Dict[str, Any]]:
    row = conn.execute(PLAN_SELECT + " WHERE p.id = ?", (plan_id,)).fetchone()
    return _row(row) if row else None


def find_by_key(conn: sqlite3.Connection, key: str) -> Optional[Dict[str, Any]]:
    row = conn.execute(PLAN_SELECT + " WHERE p.source_key = ?", (key,)).fetchone()
    return _row(row) if row else None


def create(conn: sqlite3.Connection, values: Dict[str, Any]) -> Tuple[int, bool]:
    """Insert a plan. Returns (plan id, created). An existing plan for the same key is returned instead."""
    key = source_key(values["technique"], values["rule_uid"])
    existing = find_by_key(conn, key)
    if existing:
        return existing["id"], False
    stamp = now_iso()
    try:
        cursor = conn.execute(
            """INSERT INTO rule_plan (technique, title, rule_uid, source_key, origin, priority, status,
                                      validation_status, telemetry, validation_notes, notes, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (values["technique"], values["title"], values["rule_uid"], key, values["origin"], values["priority"],
             values["status"], values["validation_status"], values["telemetry"], values["validation_notes"],
             values["notes"], stamp, stamp))
    except sqlite3.IntegrityError:
        existing = find_by_key(conn, key)  # a concurrent request created it first
        if existing:
            return existing["id"], False
        raise
    return int(cursor.lastrowid), True


def update(conn: sqlite3.Connection, plan_id: int, values: Dict[str, Any],
           expected_updated_at: str) -> Tuple[bool, Optional[str]]:
    """Whitelisted update. Returns (saved, error message)."""
    current = get(conn, plan_id)
    if current is None:
        return False, "This plan no longer exists."
    if expected_updated_at and expected_updated_at != current["updated_at"]:
        return False, "This plan changed after you opened it. Reload the page to see the latest version."
    key = source_key(values["technique"], values["rule_uid"])
    if key != current["source_key"]:
        holder = find_by_key(conn, key)
        if holder and holder["id"] != plan_id:
            return False, f"Plan #{holder['id']} already covers this rule or technique."
    try:
        cursor = conn.execute(
            """UPDATE rule_plan SET technique=?, title=?, rule_uid=?, source_key=?, priority=?, status=?,
                                    validation_status=?, telemetry=?, validation_notes=?, notes=?, updated_at=?
               WHERE id=? AND updated_at=?""",
            (values["technique"], values["title"], values["rule_uid"], key, values["priority"], values["status"],
             values["validation_status"], values["telemetry"], values["validation_notes"], values["notes"],
             now_iso(), plan_id, expected_updated_at or current["updated_at"]))
    except sqlite3.IntegrityError:
        return False, "Another plan already covers this rule or technique."
    if cursor.rowcount != 1:
        return False, "This plan changed after you opened it. Reload the page to see the latest version."
    return True, None


def list_plans(conn: sqlite3.Connection, technique: Optional[str] = None, rule_uid: Optional[str] = None,
               status: Optional[str] = None) -> List[Dict[str, Any]]:
    where, params = [], []
    if technique:
        where.append("(p.technique = ? OR p.technique = ? OR p.technique LIKE ?)")
        parent = attack.family(technique)
        params += [technique, parent, parent + ".%"]
    if rule_uid:
        where.append("p.rule_uid = ?")
        params.append(rule_uid)
    if status in STATUSES:
        where.append("p.status = ?")
        params.append(status)
    sql = PLAN_SELECT + (" WHERE " + " AND ".join(where) if where else "")
    sql += (" ORDER BY CASE p.status WHEN 'in_progress' THEN 0 WHEN 'planned' THEN 1 WHEN 'completed' THEN 2 ELSE 3 END,"
            " CASE p.priority WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, p.updated_at DESC, p.id DESC")
    return [_row(row) for row in conn.execute(sql, params)]


def status_counts(conn: sqlite3.Connection) -> Dict[str, int]:
    counts = {key: 0 for key in STATUSES}
    for row in conn.execute("SELECT status, COUNT(*) FROM rule_plan GROUP BY status"):
        counts[row[0]] = row[1]
    return counts


def plans_by_technique(conn: sqlite3.Connection) -> Dict[str, List[Dict[str, Any]]]:
    """Non-rejected plans keyed by their exact technique (Coverage and Gap Prioritization)."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for row in conn.execute(PLAN_SELECT + " WHERE p.status != 'rejected' ORDER BY p.id"):
        item = _row(row)
        out.setdefault(item["technique"], []).append(item)
    return out


def blank_form(technique: str = "", rule_uid: Optional[str] = None, title: str = "", telemetry: str = "",
               notes: str = "", origin: str = "manual", priority: str = "Medium") -> Dict[str, Any]:
    return {"technique": technique, "rule_uid": rule_uid, "title": title, "telemetry": telemetry, "notes": notes,
            "origin": origin if origin in ORIGINS else "manual", "priority": priority if priority in PRIORITIES else "Medium",
            "status": "planned", "validation_status": "not_assessed", "validation_notes": ""}
