"""Gap Prioritization: which ATT&CK technique families need rule work first, and why.

A port of the installed toolkit's explainable ranking (services/gap_navigator.py
snapshot plus candidates() and top10Status() in static/js/pages/gaps.js),
computed on the server and fed by the bundled demo data.

Family policy:
  covered  - a non-rejected plan in the family records lab validation;
  reserved - a non-rejected plan exists in the family, without lab validation;
  eligible - neither; every active member is a possible work item.
Order of eligible families (lexicographic, unchanged from the installed model):
  1. distinct reports naming a member, each at its best rank;
  2. rank points, the sum of (11 - best rank);
  3. rule content for the family in the library;
  4. family ID.
Families no report names follow only when they have rule content ("no report
priority"). Report rankings are synthetic demo data, not a threat score, and
telemetry feasibility is shown as context, never used as a weight.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional

from . import attack, plans, rules, telemetry

TOP_N = 10


def _reports(conn: sqlite3.Connection) -> Dict[str, Any]:
    reports = [dict(row) for row in conn.execute("SELECT id, name, year, note FROM threat_reports ORDER BY id")]
    memberships: Dict[str, List[Dict[str, Any]]] = {}
    for row in conn.execute("""SELECT e.report_id, e.rank, e.technique, r.name FROM threat_report_entries e
                               JOIN threat_reports r ON r.id = e.report_id ORDER BY e.report_id, e.rank"""):
        memberships.setdefault(row["technique"], []).append(
            {"report": row["report_id"], "name": row["name"], "rank": row["rank"], "technique": row["technique"]})
    return {"reports": reports, "memberships": memberships}


def _best_per_report(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    best: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        current = best.get(entry["report"])
        if current is None or entry["rank"] < current["rank"]:
            best[entry["report"]] = entry
    return sorted(best.values(), key=lambda e: (e["rank"], e["report"]))


def build(conn: sqlite3.Connection) -> Dict[str, Any]:
    report_data = _reports(conn)
    memberships = report_data["memberships"]
    by_technique = rules.rules_by_technique(conn)
    plan_map = plans.plans_by_technique(conn)
    inventory = telemetry.load_inventory(conn)
    memo: Dict[str, Any] = {}

    parents = [t["id"] for t in attack.catalog()["techniques"]
               if not t.get("is_subtechnique") and attack.is_active(t["id"])]
    candidates, excluded = [], []
    for parent in parents:
        members = attack.family_members(parent)
        family_plans = [p for m in members for p in plan_map.get(m, [])]
        family_rules = {r["uid"]: r for m in members for r in by_technique.get(m, [])}
        named = [entry for m in members for entry in memberships.get(m, [])]
        best = _best_per_report(named)
        points = sum(11 - e["rank"] for e in best)
        validated = [p for p in family_plans if p["validation_status"] == "validated"]
        if validated or family_plans:
            if not (named or family_rules):
                continue
            reason = "covered" if validated else "reserved"
            excluded.append({
                "family": parent, "family_name": attack.technique_name(parent), "reason": reason,
                "reason_label": "Covered: lab-validated plan in the family" if validated
                                else "Reserved: an open plan already covers the family",
                "plans": validated or family_plans, "reports": best, "points": points,
                "family_rule_count": len(family_rules),
            })
            continue
        if not best and not family_rules:
            continue  # no report priority and no rule content: not listed, as in the installed model
        if best:
            top = sorted(best, key=lambda e: (e["rank"], "." in e["technique"], e["technique"]))[0]
            item = top["technique"]
        elif parent in by_technique:
            item = parent
        else:
            item = sorted(members, key=lambda m: (-len(by_technique.get(m, [])), m))[0]
        feasibility = telemetry.technique_feasibility(conn, item, inventory, memo)
        exact_rules = by_technique.get(item, [])
        reasons = []
        if best:
            reasons.append(f"Named by {len(best)} of {len(report_data['reports'])} sample reports: "
                           + ", ".join(f"{e['name']} #{e['rank']} ({e['technique']})" for e in best) + ".")
            reasons.append(f"Rank points {points} = " + " + ".join(f"(11 - {e['rank']})" for e in best) + ".")
        else:
            reasons.append("No sample report names this family; it is listed because rule content exists "
                           "(availability of content, not a threat score).")
        reasons.append(f"No lab-validated rule and no open plan in family {parent} "
                       f"({len(members)} active technique{'s' if len(members) != 1 else ''}).")
        if family_rules:
            reasons.append(f"{len(family_rules)} rule{'s' if len(family_rules) != 1 else ''} in the library to adapt "
                           f"({len(exact_rules)} mapped to {item} exactly).")
        else:
            reasons.append("No rule in the library yet: a new rule has to be written.")
        reasons.append(telemetry.telemetry_summary_text(feasibility))
        if exact_rules:
            next_action = {"label": "Review the matching rule" + ("s" if len(exact_rules) > 1 else ""), "view": "rules"}
        elif family_rules:
            next_action = {"label": "Review family rules", "view": "rules_family"}
        else:
            next_action = {"label": "Create a rule plan", "view": "plan"}
        candidates.append({
            "technique": item, "name": attack.technique_name(item), "family": parent,
            "family_name": attack.technique_name(parent), "reports": best, "report_count": len(best),
            "points": points, "family_rule_count": len(family_rules), "exact_rule_count": len(exact_rules),
            "priority": "report" if best else "none", "telemetry": feasibility, "reasons": reasons,
            "next_action": next_action, "first_rule": exact_rules[0]["uid"] if exact_rules else None,
        })
    candidates.sort(key=lambda c: (-c["report_count"], -c["points"], -c["family_rule_count"], c["family"]))
    for position, candidate in enumerate(candidates, start=1):
        candidate["position"] = position
    excluded.sort(key=lambda e: (-len(e["reports"]), -e["points"], e["family"]))
    return {"candidates": candidates, "top": candidates[:TOP_N], "beyond_top": candidates[TOP_N:],
            "excluded": excluded, "reports": report_data["reports"], "memberships": memberships}


def status_text(snapshot: Dict[str, Any], technique: str) -> Dict[str, str]:
    """Why a technique is or is not a work item (adapted from top10Status in gaps.js)."""
    if not attack.is_active(technique):
        return {"state": "review", "text": "Not an active technique in the bundled ATT&CK catalog, so it is not ranked."}
    for candidate in snapshot["candidates"]:
        if candidate["technique"] == technique:
            where = f"Top {TOP_N} #{candidate['position']}" if candidate["position"] <= TOP_N \
                else f"Eligible (#{candidate['position']}, beyond the Top {TOP_N})"
            return {"state": "eligible", "text": f"{where}: the whole family has no lab-validated rule or open plan."}
    fam = attack.family(technique)
    for entry in snapshot["excluded"]:
        if entry["family"] == fam:
            ids = ", ".join(f"#{p['id']} ({p['status_label']}, {p['validation_label']})" for p in entry["plans"])
            prefix = "Covered" if entry["reason"] == "covered" else "Reserved"
            return {"state": entry["reason"], "text": f"{prefix} by plan {ids}. Not offered again as new work."}
    for candidate in snapshot["candidates"]:
        if candidate["family"] == fam:
            return {"state": "family", "text": f"The family is eligible; its work item is {candidate['technique']} "
                                               f"(#{candidate['position']})."}
    return {"state": "none", "text": "Eligible family, but no sample report names it and the library has no rule for it."}


def detail(conn: sqlite3.Connection, snapshot: Dict[str, Any], technique: Optional[str]) -> Optional[Dict[str, Any]]:
    """Inspector panel: ATT&CK context, matching rules, telemetry requirements, plans and reports."""
    if not technique:
        return None
    by_technique = rules.rules_by_technique(conn)
    context = attack.context(technique)
    family_rules = {r["uid"]: dict(r, technique=m) for m in context["family_members"] for r in by_technique.get(m, [])}
    return {
        "technique": technique,
        "context": context,
        "status": status_text(snapshot, technique),
        "exact_rules": by_technique.get(technique, []),
        "family_rules": sorted(family_rules.values(), key=lambda r: r["title"].lower()),
        "telemetry": telemetry.technique_feasibility(conn, technique),
        "plans": plans.list_plans(conn, technique=technique),
        "reports": _best_per_report(snapshot["memberships"].get(technique, [])),
        "candidate": next((c for c in snapshot["candidates"] if c["technique"] == technique), None),
    }
