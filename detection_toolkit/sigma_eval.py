"""Local sample check: a LOCAL test of one Sigma rule against supplied example events.

Copied from the installed Detection Toolkit (services/detection_validation.py, engine 1.0). Changes: the
JSON flattening helper is inlined and the isolated child runs ``python -m detection_toolkit.sigma_eval``.


Not an attack runner, not a SIEM query executor. pySigma (installed dependency) parses the rule, applies its
value modifiers and resolves the condition (selectors such as ``1 of sel*``, ``all of them``); this module
evaluates that parsed tree against flattened JSON events. Only the declared subset below is executed;
anything else is reported Unsupported and never evaluated.

Executed (event-level Sigma):
  condition: and / or / not / parentheses / ``1 of x*`` / ``all of x*`` / ``1 of them`` / ``all of them``;
    a list of conditions matches when any of them matches.
  field values: string equality with * and ? wildcards (case-insensitive; ``|cased`` is case-sensitive),
    |contains |startswith |endswith |all, |re (Python ``re`` via pySigma; flags i m s), |cidr, numbers,
    |gt |gte |lt |lte, booleans, null (field absent, JSON null or empty string), |exists,
    |fieldref (equality of two fields), and modifiers pySigma expands into plain values
    (|base64 |base64offset |wide |utf16* |windash).
  keywords (a list without field): case-insensitive, wildcard-aware search in every string value.
  lists in an event match when any element matches.
Not executed (Unsupported): correlation rules, aggregation (``| count()`` ...), ``near``, ``timeframe``,
  placeholders (|expand), rule collections with several rules, fieldref with starts/ends, unknown value types,
  and every non-Sigma query language (SPL, KQL, EQL, ES|QL, Python, ...).

Field lookup per Sigma field: explicit mapping (profile), else the exact flattened path, else a
case-insensitive path, else a unique leaf name (``EventData.CommandLine`` for ``CommandLine``). An
ambiguous leaf is reported and treated as missing; nothing is guessed.

``run_isolated`` executes the evaluation in a child process (``python -m detection_toolkit.sigma_eval``)
with CPU, memory and wall-clock limits, so a pathological regex or input cannot stall a web worker.
Uploaded content is only parsed as JSON / YAML data; nothing is executed as code.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

ENGINE = "dtk-sigma-eval"
ENGINE_VERSION = "1.0"
LIMITS = {
    "rule_bytes": 128 * 1024,
    "events_bytes": 2 * 1024 * 1024,
    "events": 500,
    "fields_per_event": 2000,
    "value_chars": 65536,
    "regex_chars": 2000,
    "mapping_entries": 200,
    "timeout_seconds": 20,
    "cpu_seconds": 15,
    "memory_bytes": 1024 * 1024 * 1024,
}
EXPECTATIONS = ("match", "no_match")
OUTCOMES = ("passed", "failed", "inconclusive", "unsupported", "invalid")
SUPPORTED_SUMMARY = (
    "Executed: event-level Sigma (and/or/not, 1 of / all of selectors, wildcards, contains/startswith/endswith/all, "
    "re, cidr, numbers and gt/gte/lt/lte, booleans, null, exists, fieldref equality, base64/base64offset/wide/windash, "
    "cased, keywords). Not executed: correlation, aggregation (| count), near, timeframe, placeholders (expand), "
    "rule collections and native SIEM query languages."
)
NOTES = (
    "A local sample test checks this rule against the supplied examples only.",
    "It does not measure a production false-positive rate, prove ATT&CK coverage or confirm a SIEM deployment.",
)


class ValidationInputError(ValueError):
    """Bad or oversized input (HTTP 400/413 at the API)."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def normalize_rule_text(text: Any) -> str:
    value = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in value.split("\n")).strip() + "\n"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rule_hash(text: Any) -> str:
    """Identity of a rule revision: sha256 of the normalized text (line endings, trailing spaces)."""
    return sha256_text(normalize_rule_text(text))


def engine_identity() -> Dict[str, str]:
    try:
        from importlib.metadata import version
        pysigma = version("pySigma")
    except Exception:  # pragma: no cover - metadata missing
        pysigma = "unknown"
    return {"engine": ENGINE, "engine_version": f"{ENGINE_VERSION} (pySigma {pysigma})"}


# ------------------------------------------------------------------------------------------------ events
def _flatten_json(value: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """JSON flattening copied from the installed services/log_analyzer.py (dotted paths; scalar lists kept)."""
    out = out if out is not None else {}
    if isinstance(value, dict):
        for key, child in value.items():
            next_key = f"{prefix}.{key}" if prefix else str(key)
            _flatten_json(child, next_key, out)
    elif isinstance(value, list):
        if all(not isinstance(item, (dict, list)) for item in value):
            out[prefix or "value"] = value
        else:
            for index, child in enumerate(value[:50]):
                _flatten_json(child, f"{prefix}[{index}]", out)
    else:
        out[prefix or "value"] = value
    return out


def _flatten(value: Any) -> Dict[str, Any]:
    """Dotted-path flattening of one event (scalar lists kept as lists)."""
    return _flatten_json(value)


def parse_events(text: str) -> Tuple[List[Dict[str, Any]], str]:
    """JSON object, JSON array of objects, or JSON Lines (one object per line). Returns (events, format)."""
    raw = str(text or "")
    if len(raw.encode("utf-8", errors="ignore")) > LIMITS["events_bytes"]:
        raise ValidationInputError(f"Sample logs exceed {LIMITS['events_bytes'] // (1024 * 1024)} MB.", 413)
    stripped = raw.strip()
    if not stripped:
        raise ValidationInputError("Paste or upload at least one JSON event.")
    try:
        parsed = json.loads(stripped)
        events, fmt = (parsed, "json-array") if isinstance(parsed, list) else ([parsed], "json")
    except json.JSONDecodeError:
        events, fmt = [], "jsonl"
        for number, line in enumerate(stripped.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValidationInputError(f"Line {number} is not valid JSON ({exc.msg}). Supported: a JSON object, "
                                           "a JSON array of objects, or JSON Lines.") from None
    if not events:
        raise ValidationInputError("No event found.")
    if len(events) > LIMITS["events"]:
        raise ValidationInputError(f"At most {LIMITS['events']} events per test.", 413)
    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValidationInputError(f"Event {index} is not a JSON object.")
    return events, fmt


def normalize_event(event: Dict[str, Any], index: int) -> Dict[str, Any]:
    flat = _flatten(event)
    if len(flat) > LIMITS["fields_per_event"]:
        raise ValidationInputError(f"Event {index} has more than {LIMITS['fields_per_event']} fields.", 413)
    for path, value in flat.items():
        values = value if isinstance(value, list) else [value]
        if any(isinstance(v, str) and len(v) > LIMITS["value_chars"] for v in values):
            raise ValidationInputError(f"Event {index} field {path[:80]} is longer than {LIMITS['value_chars']} characters.", 413)
    return flat


def field_rows(flat: Dict[str, Any]) -> List[Dict[str, Any]]:
    def kind(v):
        return ("list" if isinstance(v, list) else "null" if v is None else "boolean" if isinstance(v, bool)
                else "number" if isinstance(v, (int, float)) else "string")
    return [{"path": path, "type": kind(value), "value": value} for path, value in flat.items()]


def input_identity(events: Sequence[Dict[str, Any]], expectations: Sequence[Optional[str]]) -> str:
    canonical = json.dumps([{"event": e, "expect": x} for e, x in zip(events, expectations)],
                           sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return sha256_text(canonical)


class FieldResolver:
    def __init__(self, flat: Dict[str, Any], mapping: Dict[str, str]):
        self.flat, self.mapping = flat, mapping
        self.lower: Dict[str, List[str]] = {}
        self.leaf: Dict[str, List[str]] = {}
        for path in flat:
            self.lower.setdefault(path.casefold(), []).append(path)
            leaf = re.sub(r"\[\d+\]$", "", path.split(".")[-1]).casefold()
            self.leaf.setdefault(leaf, []).append(path)
        self.used: Dict[str, Dict[str, Any]] = {}

    def resolve(self, field: str) -> Tuple[Optional[str], str]:
        if field in self.used:
            hit = self.used[field]
            return hit["path"], hit["method"]
        target, method = field, "exact"
        if field in self.mapping:
            target, method = self.mapping[field], "mapping"
        path = None
        if target in self.flat:
            path = target
        elif len(self.lower.get(target.casefold(), [])) == 1:
            path, method = self.lower[target.casefold()][0], ("mapping" if method == "mapping" else "case-insensitive")
        elif method != "mapping":
            leaf = self.leaf.get(target.casefold(), [])
            if len(leaf) == 1:
                path, method = leaf[0], "leaf"
            elif len(leaf) > 1:
                method = "ambiguous"
        if path is None and method not in ("ambiguous",):
            method = "missing"
        self.used[field] = {"path": path, "method": method,
                            **({"candidates": self.leaf.get(target.casefold(), [])[:5]} if method == "ambiguous" else {})}
        return path, method

    def value(self, field: str) -> Tuple[bool, Any]:
        path, _method = self.resolve(field)
        if path is None:
            return False, None
        return True, self.flat[path]


# -------------------------------------------------------------------------------------------- the rule
def _load_yaml_documents(text: str) -> List[Any]:
    import yaml
    try:
        return [doc for doc in yaml.safe_load_all(text) if doc is not None]
    except yaml.YAMLError as exc:
        raise ValueError(f"Not valid YAML: {str(exc).splitlines()[0][:200]}") from None


def analyze_rule(text: str) -> Dict[str, Any]:
    """Format validation and support analysis (no events). Never raises for rule content."""
    report: Dict[str, Any] = {"format_status": "invalid", "errors": [], "warnings": [], "unsupported": [],
                              "rule": {}, "fields": [], "detections": [], "supported": False}
    rule_text = normalize_rule_text(text)
    if len(rule_text.encode("utf-8")) > LIMITS["rule_bytes"]:
        report["errors"].append(f"The rule is larger than {LIMITS['rule_bytes'] // 1024} KB.")
        return report
    try:
        docs = _load_yaml_documents(rule_text)
    except ValueError as exc:
        report["errors"].append(str(exc))
        return report
    if not docs:
        report["errors"].append("The rule is empty.")
        return report
    if any(isinstance(doc, dict) and doc.get("correlation") for doc in docs):
        report["unsupported"].append("Correlation rules (event_count, value_count, temporal ...) are not executed.")
    if len(docs) > 1:
        report["unsupported"].append("Rule collections (several YAML documents) are not executed; test one rule.")
    doc = docs[0]
    if not isinstance(doc, dict):
        report["errors"].append("A Sigma rule must be a YAML mapping.")
        return report
    missing = [key for key in ("title", "logsource", "detection") if not doc.get(key)]
    if missing and not doc.get("correlation"):
        report["errors"].append("Missing required key(s): " + ", ".join(missing))
        return report
    report["rule"] = {k: doc.get(k) for k in ("title", "id", "status", "level", "logsource") if doc.get(k) is not None}
    if doc.get("correlation"):
        report["format_status"] = "valid"
        return report
    detection = doc.get("detection") if isinstance(doc.get("detection"), dict) else {}
    conditions = detection.get("condition")
    conditions = conditions if isinstance(conditions, list) else [conditions]
    for condition in conditions:
        condition_text = str(condition or "")
        if "|" in condition_text:
            report["unsupported"].append("Aggregation in the condition (| count(), | max() ...) is not executed.")
        if re.search(r"\bnear\b", condition_text):
            report["unsupported"].append("The 'near' operator (temporal proximity) is not executed.")
    if detection.get("timeframe"):
        report["unsupported"].append("'timeframe' (a time window across events) is not executed.")
    if report["unsupported"]:
        report["format_status"] = "valid"  # structurally readable; the semantics are what is unsupported
        report["detections"] = [k for k in detection if k not in ("condition", "timeframe")]
        return report
    try:
        from sigma.rule import SigmaRule
        rule = SigmaRule.from_yaml(rule_text)
        parsed = [condition.parse() for condition in rule.detection.parsed_condition]
    except Exception as exc:  # pySigma reports structural problems with its own exception types
        report["errors"].append(f"{type(exc).__name__}: {str(exc).splitlines()[0][:300]}")
        return report
    report["format_status"] = "valid"
    report["detections"] = list(rule.detection.detections)
    fields: List[str] = []
    problems: List[str] = []
    for tree in parsed:
        _collect(tree, fields, problems)
    report["fields"] = sorted(set(fields))
    report["unsupported"].extend(sorted(set(problems)))
    report["supported"] = not report["unsupported"]
    return report


def _type(value: Any) -> str:
    return type(value).__name__


def _collect(node: Any, fields: List[str], problems: List[str]) -> None:
    name = _type(node)
    if name in ("ConditionAND", "ConditionOR", "ConditionNOT"):
        for arg in node.args:
            _collect(arg, fields, problems)
        return
    if name == "ConditionFieldEqualsValueExpression":
        fields.append(node.field)
        _check_value(node.value, problems)
        if _type(node.value) == "SigmaFieldReference":
            fields.append(node.value.field)
        return
    if name == "ConditionValueExpression":
        _check_value(node.value, problems)
        return
    problems.append(f"Unsupported condition element {name}.")


def _check_value(value: Any, problems: List[str]) -> None:
    name = _type(value)
    if name in ("SigmaString", "SigmaCasedString"):
        if value.contains_placeholder():
            problems.append("Placeholders (|expand) need values from a processing pipeline; not executed.")
        return
    if name == "SigmaExpansion":
        for item in value.values:
            _check_value(item, problems)
        return
    if name == "SigmaRegularExpression":
        if len(str(value.regexp.original)) > LIMITS["regex_chars"]:
            problems.append(f"Regular expressions longer than {LIMITS['regex_chars']} characters are not executed.")
        else:
            try:
                _regex(value)
            except Exception as exc:
                problems.append(f"Regular expression not supported by the Python engine: {str(exc)[:120]}")
        return
    if name == "SigmaFieldReference":
        if getattr(value, "starts_with", False) or getattr(value, "ends_with", False):
            problems.append("fieldref with startswith/endswith is not executed.")
        return
    if name in ("SigmaNumber", "SigmaBool", "SigmaNull", "SigmaExists", "SigmaCIDRExpression", "SigmaCompareExpression"):
        return
    problems.append(f"Value type {name} is not executed.")


# ------------------------------------------------------------------------------------------ evaluation
def _string_regex(value: Any) -> "re.Pattern[str]":
    from sigma.types import SpecialChars
    parts = []
    for part in value.s:
        if part == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            parts.append(re.escape(str(part)))
    flags = re.DOTALL | (0 if _type(value) == "SigmaCasedString" else re.IGNORECASE)
    return re.compile("".join(parts), flags)


def _as_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else str(value)


class Evaluator:
    def __init__(self):
        self.patterns: Dict[int, Any] = {}

    def pattern(self, value: Any):
        key = id(value)
        if key not in self.patterns:
            self.patterns[key] = _regex(value) if _type(value) == "SigmaRegularExpression" else _string_regex(value)
        return self.patterns[key]

    def value_matches(self, expected: Any, actual: Any, present: bool, resolver: "FieldResolver") -> bool:
        name = _type(expected)
        if name == "SigmaNull":
            return (not present) or actual is None or actual == "" or actual == []
        if name == "SigmaExists":
            return (present and actual is not None) == bool(expected.exists)
        if not present or actual is None:
            return False
        if isinstance(actual, list):
            return any(self.value_matches(expected, item, True, resolver) for item in actual)
        if name == "SigmaExpansion":
            return any(self.value_matches(item, actual, True, resolver) for item in expected.values)
        if name in ("SigmaString", "SigmaCasedString"):
            return bool(self.pattern(expected).fullmatch(_text(actual)))
        if name == "SigmaRegularExpression":
            return bool(self.pattern(expected).search(_text(actual)))
        if name == "SigmaNumber":
            number = _as_number(actual)
            return number is not None and number == float(expected.number)
        if name == "SigmaBool":
            return (actual is expected.boolean) if isinstance(actual, bool) else _text(actual).strip().casefold() == str(expected.boolean).casefold()
        if name == "SigmaCIDRExpression":
            try:
                return ipaddress.ip_address(_text(actual).strip()) in expected.network
            except ValueError:
                return False
        if name == "SigmaCompareExpression":
            number = _as_number(actual)
            if number is None:
                return False
            op, limit = expected.op.name, float(expected.number.number)
            return {"LT": number < limit, "LTE": number <= limit, "GT": number > limit, "GTE": number >= limit}[op]
        if name == "SigmaFieldReference":
            present_other, other = resolver.value(expected.field)
            if not present_other or other is None:
                return False
            return _text(actual).casefold() == _text(other).casefold()
        raise RuntimeError(f"unsupported value type {name}")  # analyze_rule refuses these first

    def node(self, node: Any, resolver: FieldResolver, selections: Dict[str, bool]) -> bool:
        name = _type(node)
        if name == "ConditionAND":
            result = all([self.node(arg, resolver, selections) for arg in node.args])
        elif name == "ConditionOR":
            result = any([self.node(arg, resolver, selections) for arg in node.args])
        elif name == "ConditionNOT":
            result = not self.node(node.args[0], resolver, selections)
        elif name == "ConditionFieldEqualsValueExpression":
            present, actual = resolver.value(node.field)
            result = self.value_matches(node.value, actual, present, resolver)
        elif name == "ConditionValueExpression":
            pattern = _keyword_regex(node.value) if _type(node.value) != "SigmaExpansion" else None
            values = [v for value in resolver.flat.values() for v in (value if isinstance(value, list) else [value])
                      if isinstance(v, (str, int, float)) and not isinstance(v, bool)]
            if pattern is None:
                result = any(_keyword_regex(item).search(_text(v)) for item in node.value.values for v in values)
            else:
                result = any(pattern.search(_text(v)) for v in values)
        else:
            raise RuntimeError(f"unsupported condition element {name}")
        # Post-order: the selection's top node is evaluated last, so its value is the one kept.
        identifier = _selection_of(node)
        if identifier:
            selections[identifier] = bool(result)
        return result


def _selection_of(node: Any) -> Optional[str]:
    """Name of the detection (selection) a parsed node belongs to: up through SigmaDetectionItem/SigmaDetection."""
    parent = getattr(node, "parent", None)
    while _type(parent) in ("SigmaDetectionItem", "SigmaDetection"):
        parent = getattr(parent, "parent", None)
    return getattr(parent, "identifier", None) if _type(parent) == "ConditionIdentifier" else None


def _regex(value: Any) -> "re.Pattern[str]":
    """Compiled exactly as pySigma's SigmaRegularExpression.compile() validates it (str(regexp) + its flag map)."""
    flags = 0
    for flag in value.flags:
        flags |= value.sigma_to_python_flags[flag]
    return re.compile(str(value.regexp), flags)


def _keyword_regex(value: Any):
    from sigma.types import SpecialChars
    parts = [".*" if p == SpecialChars.WILDCARD_MULTI else "." if p == SpecialChars.WILDCARD_SINGLE else re.escape(str(p))
             for p in value.s]
    return re.compile("".join(parts), re.DOTALL | (0 if _type(value) == "SigmaCasedString" else re.IGNORECASE))


def _clean_mapping(mapping: Any) -> Dict[str, str]:
    if mapping in (None, "", {}):
        return {}
    if not isinstance(mapping, dict):
        raise ValidationInputError("The field mapping must be a JSON object {\"SigmaField\": \"event.path\"}.")
    if len(mapping) > LIMITS["mapping_entries"]:
        raise ValidationInputError(f"At most {LIMITS['mapping_entries']} field mappings.")
    out = {}
    for key, value in mapping.items():
        if not isinstance(key, str) or not isinstance(value, str) or not key.strip() or not value.strip():
            raise ValidationInputError("Every field mapping entry must map a Sigma field name to an event path (text).")
        out[key.strip()[:200]] = value.strip()[:300]
    return out


def evaluate(rule_text: str, events: Sequence[Dict[str, Any]], expectations: Sequence[Optional[str]],
             mapping: Optional[Dict[str, str]] = None, labels: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Evaluate one rule against events with recorded expectations ('match', 'no_match' or None)."""
    mapping = _clean_mapping(mapping)
    if len(expectations) != len(events):
        raise ValidationInputError("Give one expectation per event (match, no_match or none).")
    for value in expectations:
        if value is not None and value not in EXPECTATIONS:
            raise ValidationInputError("An expectation must be 'match', 'no_match' or empty.")
    analysis = analyze_rule(rule_text)
    result: Dict[str, Any] = {**engine_identity(), "analysis": analysis, "mapping": mapping, "events": [],
                              "supported_subset": SUPPORTED_SUMMARY, "notes": list(NOTES)}
    counts = {"events": len(events), "attack": 0, "benign": 0, "unlabeled": 0, "tp": 0, "fn": 0, "fp": 0, "tn": 0}
    for value in expectations:
        counts["attack" if value == "match" else "benign" if value == "no_match" else "unlabeled"] += 1
    result["counts"] = counts
    if analysis["format_status"] != "valid":
        return {**result, "outcome": "invalid", "reasons": analysis["errors"] or ["The rule could not be read."]}
    if analysis["unsupported"]:
        return {**result, "outcome": "unsupported", "reasons": ["Not executed: " + reason for reason in analysis["unsupported"]]}
    from sigma.rule import SigmaRule
    rule = SigmaRule.from_yaml(normalize_rule_text(rule_text))
    trees = [condition.parse() for condition in rule.detection.parsed_condition]
    evaluator = Evaluator()
    field_presence: Dict[str, Dict[str, int]] = {f: {"present": 0, "missing": 0, "ambiguous": 0} for f in analysis["fields"]}
    for index, (event, expect) in enumerate(zip(events, expectations)):
        flat = normalize_event(event, index + 1)
        resolver = FieldResolver(flat, mapping)
        selections: Dict[str, bool] = {}
        matched = any([evaluator.node(tree, resolver, selections) for tree in trees])
        fields = {}
        for field in analysis["fields"]:
            path, method = resolver.resolve(field)
            fields[field] = {"path": path, "method": method}
            field_presence[field]["present" if path else "ambiguous" if method == "ambiguous" else "missing"] += 1
        outcome = ("unlabeled" if expect is None else "tp" if expect == "match" and matched else "fn" if expect == "match"
                   else "fp" if matched else "tn")
        if outcome != "unlabeled":
            counts[outcome] += 1
        result["events"].append({"index": index + 1, "label": (labels[index] if labels and index < len(labels) else "") or "",
                                 "expect": expect, "matched": matched, "outcome": outcome,
                                 "selections": dict(sorted(selections.items())), "fields": fields})
    result["field_summary"] = field_presence
    reasons: List[str] = []
    if counts["fn"]:
        reasons.append(f"{counts['fn']} attack example(s) did not match.")
    if counts["fp"]:
        reasons.append(f"{counts['fp']} benign example(s) matched unexpectedly.")
    never = [f for f, c in field_presence.items() if not c["present"]]
    if reasons:
        if never:
            reasons.append("Field(s) never found in the events: " + ", ".join(never[:10]) + " (check the field mapping).")
        return {**result, "outcome": "failed", "reasons": reasons}
    if not counts["attack"] and not counts["benign"]:
        return {**result, "outcome": "inconclusive", "reasons": ["No example is labelled: label attack (should match) and benign (should not match) events."]}
    if not counts["attack"]:
        return {**result, "outcome": "inconclusive",
                "reasons": ["No attack example: a detection test needs at least one event that should match."]}
    reasons.append(f"{counts['tp']} of {counts['attack']} attack example(s) matched"
                   + (f"; {counts['tn']} of {counts['benign']} benign example(s) did not match." if counts["benign"]
                      else "; no benign example was supplied, so false positives were not tested."))
    return {**result, "outcome": "passed", "reasons": reasons}


# ------------------------------------------------------------------------------------- isolated child
def _child_limits() -> None:
    try:
        import resource
        cpu = LIMITS["cpu_seconds"]
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        memory = LIMITS["memory_bytes"]
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    except Exception:  # pragma: no cover - platform without resource limits
        pass


def run_isolated(payload: Dict[str, Any], timeout: Optional[int] = None) -> Dict[str, Any]:
    """evaluate() in a child process with CPU/memory/wall-clock limits. Raises RuntimeError on engine failure."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": root, "PYTHONDONTWRITEBYTECODE": "1",
           "LANG": "C.UTF-8", "HOME": os.environ.get("HOME", root)}
    try:
        proc = subprocess.run([sys.executable, "-m", "detection_toolkit.sigma_eval"], input=json.dumps(payload).encode("utf-8"),
                              capture_output=True, cwd=root, env=env, timeout=timeout or LIMITS["timeout_seconds"], check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"The evaluation exceeded {timeout or LIMITS['timeout_seconds']} s and was stopped "
                           "(simplify the regular expressions or reduce the sample).") from None
    except OSError as exc:
        raise RuntimeError(f"The evaluation engine could not start: {exc}") from None
    try:
        reply = json.loads(proc.stdout.decode("utf-8") or "{}")
    except ValueError:
        reply = {}
    if proc.returncode != 0 or not reply.get("ok"):
        if reply.get("input_error"):
            raise ValidationInputError(reply["input_error"], int(reply.get("status") or 400))
        detail = reply.get("error") or ("CPU or memory limit reached" if proc.returncode < 0 else "engine error")
        raise RuntimeError(f"The evaluation failed: {detail}")
    return reply["result"]


def _main() -> int:
    _child_limits()
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        result = evaluate(payload.get("rule_text", ""), payload.get("events") or [], payload.get("expectations") or [],
                          payload.get("mapping") or {}, payload.get("labels") or [])
        sys.stdout.write(json.dumps({"ok": True, "result": result}, ensure_ascii=False, default=str))
        return 0
    except ValidationInputError as exc:
        sys.stdout.write(json.dumps({"ok": False, "input_error": str(exc), "status": exc.status}))
        return 0
    except MemoryError:
        sys.stdout.write(json.dumps({"ok": False, "error": "memory limit reached"}))
        return 3
    except Exception as exc:
        sys.stdout.write(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}))
        return 2


if __name__ == "__main__":
    sys.exit(_main())
