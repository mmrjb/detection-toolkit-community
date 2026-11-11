"""Read metadata out of a parsed Sigma rule.

``flatten_strings``, the Sigma branch of ``extract_techniques`` and
``extract_sigma_required_fields`` are copied from the installed app.py; the
other feed branches (Splunk, Elastic, Sentinel, ...) are omitted because the
edition only bundles Sigma content.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Set

from .attack import ATTACK_TAG_RE, TECHNIQUE_RE

URL_PATH_ID_RE = re.compile(r"\b(T\d{4})/(\d{3})\b", re.IGNORECASE)


def flatten_strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from flatten_strings(v)
    elif isinstance(obj, (list, tuple, set)):
        for item in obj:
            yield from flatten_strings(item)
    elif obj is not None:
        yield str(obj)


def extract_techniques(data: Dict[str, Any]) -> Set[str]:
    """ATT&CK technique IDs from Sigma tags, plus the conservative fallback over every string."""
    techniques: Set[str] = set()

    def add(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                add(item)
            return
        if isinstance(value, dict):
            for key in ("id", "reference", "name"):
                add(value.get(key))
            for key in ("subtechnique", "subtechniques"):
                add(value.get(key))
            return
        for match in TECHNIQUE_RE.findall(str(value)):
            techniques.add(match.upper())

    add(data.get("tags"))
    # Conservative fallback: search for explicit Txxxx IDs or attack.txxxx tags. Unlike the installed
    # version it skips ``references`` (an ATT&CK URL such as .../techniques/T1059/001/ would otherwise
    # add the parent T1059) and reads a "T1059/001" path as T1059.001.
    for text in flatten_strings({key: value for key, value in data.items() if key != "references"}):
        text = URL_PATH_ID_RE.sub(r"\1.\2", text)
        for attack_tag in ATTACK_TAG_RE.findall(text):
            add(attack_tag)
        for tech in TECHNIQUE_RE.findall(text):
            add(tech)
    return {t.upper() for t in techniques}


def extract_sigma_required_fields(data: Dict[str, Any]) -> List[str]:
    """Field names used in the detection block, without value modifiers (``Image|endswith`` -> ``Image``)."""
    fields: Set[str] = set()
    detection = data.get("detection") or {}
    if not isinstance(detection, dict):
        return []
    for key, value in detection.items():
        if key in {"condition", "timeframe"}:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, dict):
                for raw_field in item.keys():
                    fields.add(str(raw_field).split("|")[0])
    return sorted(fields)


def logsource_of(data: Dict[str, Any]) -> Dict[str, str]:
    raw = data.get("logsource") if isinstance(data.get("logsource"), dict) else {}
    return {key: str(raw.get(key) or "").strip().lower() for key in ("product", "category", "service")}


def logsource_label(product: str, category: str, service: str) -> str:
    parts = [f"{name}: {value}" for name, value in (("product", product), ("category", category), ("service", service)) if value]
    return ", ".join(parts) or "not specified"


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
