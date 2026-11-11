"""ATT&CK Coverage: which techniques have rule content, and which have lab validation.

The two are kept apart on purpose. Rule content means a rule in the library
is mapped to the technique (the installed toolkit's public-feed count:
mitre_index joined to rules). Lab validated means a non-rejected Rule Plan
records validation evidence for that exact technique. Neither one means a
detection is deployed.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional

from . import attack, plans, rules

STATE_FILTERS = {
    "all": "All techniques",
    "content": "Has rule content",
    "no_content": "No rule content",
    "validated": "Lab validated",
    "content_not_validated": "Rule content, not lab validated",
}


def _validation_state(technique_plans: List[Dict[str, Any]]) -> Dict[str, Any]:
    validated = [p for p in technique_plans if p["validation_status"] == "validated"]
    if validated:
        return {"state": "validated", "label": "Lab validated", "plan": validated[0]}
    if technique_plans:
        plan = technique_plans[0]
        return {"state": "planned", "label": f"In a plan, not validated ({plan['validation_label']})", "plan": plan}
    return {"state": "none", "label": "Not lab validated", "plan": None}


def build(conn: sqlite3.Connection, tactic: Optional[str] = None, state: str = "all",
          selected: Optional[str] = None) -> Dict[str, Any]:
    by_technique = rules.rules_by_technique(conn)
    plan_map = plans.plans_by_technique(conn)
    tactic_names = attack.tactic_names()
    rows = []
    for info in attack.catalog()["techniques"]:
        if info.get("revoked") or info.get("deprecated"):
            continue
        technique = info["id"]
        exact = by_technique.get(technique, [])
        family_rules: Dict[str, str] = {}
        if not info.get("is_subtechnique"):
            for member in attack.family_members(technique):
                for rule in by_technique.get(member, []):
                    family_rules[rule["uid"]] = rule["title"]
        validation = _validation_state(plan_map.get(technique, []))
        rows.append({
            "technique": technique, "name": info["name"], "parent": info.get("parent") or technique,
            "is_subtechnique": bool(info.get("is_subtechnique")),
            "tactics": [tactic_names.get(t, t) for t in info.get("tactics", [])],
            "tactic_keys": list(info.get("tactics", [])),
            "rule_count": len(exact), "rules": exact, "family_rule_count": len(family_rules),
            "validation": validation,
        })
    summary = {
        "techniques": len(rows),
        "with_content": sum(1 for r in rows if r["rule_count"]),
        "validated": sum(1 for r in rows if r["validation"]["state"] == "validated"),
        "content_not_validated": sum(1 for r in rows if r["rule_count"] and r["validation"]["state"] != "validated"),
        "no_content": sum(1 for r in rows if not r["rule_count"]),
        "rules": conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0],
    }
    used_tactics = [(key, name) for key, name in tactic_names.items() if any(key in r["tactic_keys"] for r in rows)]
    visible = rows
    if tactic and tactic in dict(used_tactics):
        visible = [r for r in visible if tactic in r["tactic_keys"]]
    if state == "content":
        visible = [r for r in visible if r["rule_count"]]
    elif state == "no_content":
        visible = [r for r in visible if not r["rule_count"]]
    elif state == "validated":
        visible = [r for r in visible if r["validation"]["state"] == "validated"]
    elif state == "content_not_validated":
        visible = [r for r in visible if r["rule_count"] and r["validation"]["state"] != "validated"]
    selected_row = next((r for r in rows if r["technique"] == selected), None) if selected else None
    return {"rows": visible, "summary": summary, "tactics": used_tactics, "selected": selected_row,
            "attack_version": attack.catalog().get("version", "")}
