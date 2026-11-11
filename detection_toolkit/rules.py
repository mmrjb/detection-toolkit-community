"""Rule library queries for Rule Search and the other views.

Adapted from the installed services/rule_search.py: ``escape_like`` and the
keyword / ATT&CK filters are kept, ``family_terms`` keeps the catalog-plus-
mapped-IDs expansion, and a log-source filter (product, category, service) is
added because the installed search had none.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import attack
from .sigma_meta import logsource_label

PAGE_SIZE = 25
MAX_QUERY_LENGTH = 200
SCOPES = ("exact", "family")
LOGSOURCE_VALUE_RE = re.compile(r"[a-z0-9_.-]{1,64}")
PAGE_RE = re.compile(r"[0-9]{1,6}")
UID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def uid_param(value: Any) -> Optional[str]:
    text = str(value or "").strip().lower()
    return text if UID_RE.fullmatch(text) else None


@dataclass
class RuleQuery:
    q: str = ""
    technique: str = ""
    scope: str = "exact"
    product: str = ""
    category: str = ""
    service: str = ""
    source: str = ""
    page: int = 1
    technique_terms: List[str] = field(default_factory=list)

    def is_filtered(self) -> bool:
        return any((self.q, self.technique, self.product, self.category, self.service, self.source))


def parse_query(args: Any) -> Tuple[RuleQuery, List[str]]:
    """Validated filters from request args; invalid values are dropped with a readable message."""
    errors: List[str] = []
    query = RuleQuery()
    q = str(args.get("q") or "").strip()
    if len(q) > MAX_QUERY_LENGTH:
        errors.append(f"The keyword was shortened to {MAX_QUERY_LENGTH} characters.")
        q = q[:MAX_QUERY_LENGTH]
    query.q = q
    raw_technique = str(args.get("technique") or "").strip()
    try:
        query.technique = attack.clean_technique(raw_technique)
    except ValueError as exc:
        errors.append(f"ATT&CK ID ignored: {exc}")
    scope = str(args.get("scope") or "exact").strip().lower()
    query.scope = scope if scope in SCOPES else "exact"
    for name in ("product", "category", "service"):
        value = str(args.get(name) or "").strip().lower()
        if value and not LOGSOURCE_VALUE_RE.fullmatch(value):
            errors.append(f"Log source {name} ignored: use letters, digits, '_', '.' or '-'.")
            value = ""
        setattr(query, name, value)
    source = str(args.get("source") or "").strip().lower()
    query.source = source if source and LOGSOURCE_VALUE_RE.fullmatch(source) else ""
    page_text = str(args.get("page") or "1").strip()
    query.page = int(page_text) if PAGE_RE.fullmatch(page_text) and int(page_text) >= 1 else 1
    return query, errors


def link_args(query: RuleQuery) -> Dict[str, Any]:
    """The validated filters, for building result and pager links (never the raw query string)."""
    values = {"q": query.q, "technique": query.technique, "scope": query.scope if query.technique else "",
              "product": query.product, "category": query.category, "service": query.service,
              "source": query.source, "page": query.page if query.page > 1 else ""}
    return {key: value for key, value in values.items() if value}


def family_terms(conn: sqlite3.Connection, technique: str) -> List[str]:
    """The parent family of ``technique``: catalog parent, input, catalog children and mapped parent.* IDs."""
    parent = attack.family(technique)
    terms = {parent, technique}
    terms.update(t for t, info in attack.technique_index().items() if info.get("parent") == parent)
    terms.update(row[0] for row in conn.execute(
        "SELECT DISTINCT technique FROM mitre_index WHERE technique = ? OR (technique > ? AND technique < ?)",
        (parent, parent + ".", parent + "/")))
    return sorted(t for t in terms if attack.STRICT_TECHNIQUE_RE.fullmatch(t))


def _filters(conn: sqlite3.Connection, query: RuleQuery) -> Tuple[str, List[Any]]:
    where: List[str] = []
    params: List[Any] = []
    if query.q:
        like = "%" + escape_like(query.q) + "%"
        where.append("(r.title LIKE ? ESCAPE '\\' OR r.rule_id LIKE ? ESCAPE '\\' "
                     "OR r.description LIKE ? ESCAPE '\\' OR r.raw_yaml LIKE ? ESCAPE '\\')")
        params += [like, like, like, like]
    if query.technique:
        terms = family_terms(conn, query.technique) if query.scope == "family" else [query.technique]
        query.technique_terms = terms
        where.append(f"r.uid IN (SELECT rule_uid FROM mitre_index WHERE technique IN ({','.join('?' * len(terms))}))")
        params += terms
    for column, value in (("logsource_product", query.product), ("logsource_category", query.category),
                          ("logsource_service", query.service)):
        if value:
            where.append(f"r.{column} = ?")
            params.append(value)
    if query.source:
        where.append("r.source_id = ?")
        params.append(query.source)
    return (" AND ".join(where) if where else "1=1"), params


def _techniques_for(conn: sqlite3.Connection, uids: List[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {uid: [] for uid in uids}
    if not uids:
        return out
    marks = ",".join("?" * len(uids))
    for row in conn.execute(f"SELECT rule_uid, technique FROM mitre_index WHERE rule_uid IN ({marks}) "
                            "ORDER BY technique", uids):
        out[row["rule_uid"]].append(row["technique"])
    return out


def _summary(row: sqlite3.Row, techniques: List[str]) -> Dict[str, Any]:
    return {
        "uid": row["uid"], "title": row["title"], "rule_id": row["rule_id"], "level": row["level"],
        "status": row["status"], "source_id": row["source_id"], "source_name": row["source_name"],
        "logsource": {"product": row["logsource_product"], "category": row["logsource_category"],
                      "service": row["logsource_service"]},
        "logsource_label": logsource_label(row["logsource_product"], row["logsource_category"], row["logsource_service"]),
        "techniques": techniques,
    }


SELECT_COLUMNS = ("r.uid, r.title, r.rule_id, r.level, r.status, r.source_id, s.name AS source_name, "
                  "r.logsource_product, r.logsource_category, r.logsource_service")


def search(conn: sqlite3.Connection, query: RuleQuery) -> Dict[str, Any]:
    where, params = _filters(conn, query)
    total = conn.execute(f"SELECT COUNT(*) FROM rules r WHERE {where}", params).fetchone()[0]
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(query.page, pages)
    rows = conn.execute(
        f"SELECT {SELECT_COLUMNS} FROM rules r JOIN sources s ON s.id = r.source_id WHERE {where} "
        "ORDER BY r.title COLLATE NOCASE, r.uid LIMIT ? OFFSET ?",
        params + [PAGE_SIZE, (page - 1) * PAGE_SIZE]).fetchall()
    techniques = _techniques_for(conn, [row["uid"] for row in rows])
    return {"rows": [_summary(row, techniques[row["uid"]]) for row in rows], "total": total,
            "page": page, "pages": pages, "technique_terms": query.technique_terms}


def facets(conn: sqlite3.Connection) -> Dict[str, List[Tuple[str, int]]]:
    out: Dict[str, List[Tuple[str, int]]] = {}
    for name, column in (("product", "logsource_product"), ("category", "logsource_category"),
                         ("service", "logsource_service")):
        out[name] = [(row[0], row[1]) for row in conn.execute(
            f"SELECT {column}, COUNT(*) FROM rules WHERE {column} != '' GROUP BY {column} ORDER BY {column}")]
    out["source"] = [(row[0], row[1]) for row in conn.execute(
        "SELECT s.id, COUNT(r.uid) FROM sources s LEFT JOIN rules r ON r.source_id = s.id GROUP BY s.id ORDER BY s.name")]
    return out


def source_names(conn: sqlite3.Connection) -> Dict[str, str]:
    return {row["id"]: row["name"] for row in conn.execute("SELECT id, name FROM sources")}


def get_rule(conn: sqlite3.Connection, uid: Optional[str]) -> Optional[Dict[str, Any]]:
    """One rule with its YAML, ATT&CK IDs and full source attribution."""
    if not uid:
        return None
    row = conn.execute(
        """SELECT r.*, s.name AS source_name, s.license AS source_license, s.license_url AS source_license_url,
                  s.homepage AS source_homepage, s.notice AS source_notice
           FROM rules r JOIN sources s ON s.id = r.source_id WHERE r.uid = ?""", (uid,)).fetchone()
    if row is None:
        return None
    rule = _summary(row, _techniques_for(conn, [uid])[uid])
    rule.update({
        "description": row["description"], "author": row["author"], "rule_date": row["rule_date"],
        "modified": row["modified"], "file_path": row["file_path"], "reference_url": row["reference_url"],
        "raw_yaml": row["raw_yaml"], "content_hash": row["content_hash"],
        "attribution": {"source": row["source_name"], "license": row["source_license"],
                        "license_url": row["source_license_url"], "homepage": row["source_homepage"],
                        "notice": row["source_notice"], "author": row["author"], "file_path": row["file_path"],
                        "reference_url": row["reference_url"]},
    })
    return rule


def rule_choices(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    rows = conn.execute("SELECT uid, title FROM rules ORDER BY title COLLATE NOCASE").fetchall()
    techniques = _techniques_for(conn, [row["uid"] for row in rows])
    return [{"uid": row["uid"], "title": row["title"], "techniques": techniques[row["uid"]]} for row in rows]


def rule_title(conn: sqlite3.Connection, uid: Optional[str]) -> Optional[str]:
    if not uid:
        return None
    row = conn.execute("SELECT title FROM rules WHERE uid = ?", (uid,)).fetchone()
    return row["title"] if row else None


def rules_by_technique(conn: sqlite3.Connection) -> Dict[str, List[Dict[str, str]]]:
    """Exact technique -> [{uid, title}] for every mapped rule."""
    out: Dict[str, List[Dict[str, str]]] = {}
    for row in conn.execute("SELECT m.technique, r.uid, r.title FROM mitre_index m JOIN rules r ON r.uid = m.rule_uid "
                            "ORDER BY r.title COLLATE NOCASE"):
        out.setdefault(row["technique"], []).append({"uid": row["uid"], "title": row["title"]})
    return out
