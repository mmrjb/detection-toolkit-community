"""ATT&CK reference data and technique-ID helpers.

The bundled catalog is a subset of MITRE ATT&CK Enterprise in the same shape
as the installed toolkit's static/data/attack-catalog-19.2.json. ``catalog``,
``technique_index``, ``family`` and ``clean_technique`` follow
services/feed_intelligence.py; the regular expressions and
``normalize_technique`` come from the installed app.py.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional

from .config import SEED_DIR

CATALOG_FILE = SEED_DIR / "attack-catalog-subset.json"
ATTACK_BASE_URL = "https://attack.mitre.org"

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
ATTACK_TAG_RE = re.compile(r"attack\.t\d{4}(?:\.\d{3})?", re.IGNORECASE)
STRICT_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


@lru_cache(maxsize=1)
def catalog() -> Dict[str, Any]:
    data = json.loads(CATALOG_FILE.read_text(encoding="utf-8"))
    if not isinstance(data.get("techniques"), list) or not isinstance(data.get("tactics"), list):
        raise RuntimeError(f"{CATALOG_FILE} is not an ATT&CK catalog file")
    return data


@lru_cache(maxsize=1)
def technique_index() -> Dict[str, Dict[str, Any]]:
    return {t["id"]: t for t in catalog()["techniques"]}


@lru_cache(maxsize=1)
def tactic_names() -> Dict[str, str]:
    """Tactic shortname -> display name, in ATT&CK matrix order."""
    return {t["shortname"]: t["name"] for t in catalog()["tactics"]}


def family(technique: str) -> str:
    t = str(technique or "").strip().upper()
    return technique_index().get(t, {}).get("parent") or t.split(".")[0]


def clean_technique(value: Any) -> str:
    """'' for no value, the upper-cased ID for a valid one, ValueError otherwise."""
    t = str(value or "").strip().upper()
    if t and not STRICT_TECHNIQUE_RE.fullmatch(t):
        raise ValueError("Use an ATT&CK technique ID such as T1059 or T1059.001.")
    return t


def technique_param(value: Any) -> Optional[str]:
    """A technique ID from a URL parameter, or None when absent or malformed."""
    try:
        return clean_technique(value) or None
    except ValueError:
        return None


def normalize_technique(value: str) -> Optional[str]:
    if not value:
        return None
    value = value.strip().lower().replace("attack.", "")
    match = TECHNIQUE_RE.search(value)
    return match.group(0).upper() if match else None


def is_active(technique: str) -> bool:
    info = technique_index().get(technique)
    return bool(info and not info.get("revoked") and not info.get("deprecated"))


def technique_name(technique: str) -> str:
    return technique_index().get(technique, {}).get("name", "")


def family_members(parent: str) -> List[str]:
    """Active parent and sub-techniques of a family, parent first."""
    members = [t["id"] for t in catalog()["techniques"]
               if t.get("parent") == parent and not t.get("revoked") and not t.get("deprecated")]
    return sorted(members, key=lambda tid: (tid != parent, tid))


def technique_tactics(technique: str) -> List[str]:
    names = tactic_names()
    return [names.get(short, short) for short in technique_index().get(technique, {}).get("tactics", [])]


def technique_url(technique: str) -> str:
    """ATT&CK Enterprise page for Txxxx or Txxxx.xxx (adapted from mitre_technique_url)."""
    match = re.fullmatch(r"T(\d{4})(?:\.(\d{3}))?", str(technique or "").upper())
    if not match:
        return f"{ATTACK_BASE_URL}/techniques/"
    base, sub = match.group(1), match.group(2)
    return f"{ATTACK_BASE_URL}/techniques/T{base}/{sub}/" if sub else f"{ATTACK_BASE_URL}/techniques/T{base}/"


def context(technique: str) -> Dict[str, Any]:
    """ATT&CK context for one technique: name, tactics, platforms, family and the public page."""
    info = technique_index().get(technique, {})
    parent = family(technique)
    return {
        "technique": technique,
        "name": info.get("name", ""),
        "known": bool(info),
        "active": is_active(technique),
        "is_subtechnique": "." in technique,
        "family": parent,
        "family_name": technique_name(parent),
        "family_members": family_members(parent),
        "tactics": technique_tactics(technique),
        "platforms": info.get("platforms", []),
        "url": technique_url(technique),
        "attack_version": catalog().get("version", ""),
    }
