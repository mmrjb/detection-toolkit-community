"""Sigma to Splunk SPL conversion through pySigma.

Copied from the installed app.py conversion path (parse_rule_converter_source,
sigma_rule_validation, normalize_pysigma_pipeline, load_pysigma_pipeline,
normalize_pysigma_output, pysigma_convert_collection, run_pysigma_conversion,
score_converted_rule, sigma_to_siem_pysigma) with these changes:

* Only the Splunk target is kept (the other targets were omitted features).
* ``backend.errors`` is read after every conversion. With collect_errors=True
  the installed code returned an empty query and no warning when pySigma
  rejected a rule; here the first error becomes a readable ConversionError.
* The savedsearches.conf pass uses its own backend, so errors do not pile up.
* YAML syntax errors report the line and column; input is capped at 256 KiB and
  YAML aliases are refused, so a small paste cannot expand into a huge document.
* ``convert_isolated`` runs pySigma in a child process with CPU, memory and time
  limits (the same approach as the local sample check), because modifiers such
  as windash can expand a short rule into a very large number of values.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .attack import TECHNIQUE_RE
from .sigma_meta import extract_sigma_required_fields, extract_techniques, flatten_strings

MAX_SIGMA_BYTES = 256 * 1024
CHILD_LIMITS = {"timeout_seconds": 30, "cpu_seconds": 20, "memory_bytes": 1024 * 1024 * 1024}
logger = logging.getLogger("detection_toolkit.converter")

PYSIGMA_PIPELINE_LABELS = {
    "splunk_windows": "Splunk Windows pipeline (pySigma splunk_windows_pipeline)",
    "splunk_none": "No pipeline (Sigma field names as written)",
}
DEFAULT_PIPELINE = "splunk_windows"


def _first_line(exc: BaseException) -> str:
    text = str(exc).strip()
    return text.splitlines()[0] if text else type(exc).__name__


class ConversionError(ValueError):
    """A problem with the submitted rule, shown to the user as-is."""


class ConverterUnavailable(RuntimeError):
    """pySigma or the Splunk backend is not installed in this Python environment."""


class ConverterFailure(RuntimeError):
    """The converter process failed for a reason that is not the rule's fault (logged on the server)."""


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader that refuses anchors and aliases (no "billion laughs" expansion)."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.composer.ComposerError(None, None, "YAML aliases (*name) are not accepted", event.start_mark)
        return super().compose_node(parent, index)


def normalize_newlines(text: str) -> str:
    return str(text or "").replace("\r\n", "\n").replace("\r", "\n")


def parse_rule_converter_source(text: str) -> Dict[str, Any]:
    text = normalize_newlines(text).strip()
    if not text:
        raise ConversionError("Paste a Sigma rule in YAML, or open one from Rule Search.")
    if len(text.encode("utf-8")) > MAX_SIGMA_BYTES:
        raise ConversionError(f"The rule is larger than {MAX_SIGMA_BYTES // 1024} KiB. Convert one rule at a time.")
    try:
        documents = [doc for doc in yaml.load_all(text, Loader=_NoAliasSafeLoader) if doc is not None]
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        problem = getattr(exc, "problem", None) or _first_line(exc)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark is not None else ""
        raise ConversionError(f"YAML syntax error{where}: {problem}.") from None
    except MemoryError:
        raise
    except Exception as exc:  # e.g. an impossible date (2024-02-30) or a malformed !!bool / !!timestamp value
        raise ConversionError(f"The YAML contains a value that cannot be read: {_first_line(exc)}.") from None
    if not documents:
        raise ConversionError("The YAML is empty.")
    if len(documents) > 1:
        raise ConversionError("This input holds several YAML documents. Paste a single Sigma rule.")
    data = documents[0]
    if not isinstance(data, dict):
        raise ConversionError("A Sigma rule must be a YAML mapping with keys such as title, logsource and detection.")
    return data


def sigma_rule_validation(data: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    required = ["title", "logsource", "detection"]
    for key in required:
        if not data.get(key):
            errors.append(f"Missing required Sigma field: {key}")
    detection = data.get("detection")
    if isinstance(detection, dict) and not detection.get("condition"):
        warnings.append("Detection block has no explicit condition. pySigma may use backend defaults or fail depending on the rule structure.")
    if not data.get("id"):
        warnings.append("Rule has no id field.")
    if not data.get("status"):
        warnings.append("Rule has no status field.")
    elif str(data.get("status")).lower() in {"experimental", "test"}:
        warnings.append("Rule status is experimental/test. Review carefully before production use.")
    tags = data.get("tags") or []
    tag_text = " ".join(flatten_strings(tags)).lower()
    if "attack." not in tag_text and not TECHNIQUE_RE.search(tag_text):
        warnings.append("No MITRE ATT&CK tag was found in the rule metadata.")
    if not data.get("falsepositives"):
        warnings.append("Rule has no falsepositives section. Add tuning notes before deployment.")
    if not data.get("level"):
        warnings.append("Rule has no level/severity field.")
    return errors, warnings


def validate_rule(data: Dict[str, Any]) -> List[str]:
    """Run sigma_rule_validation; raise ConversionError for missing keys or unreadable values. Returns warnings."""
    try:
        errors, warnings = sigma_rule_validation(data)
    except MemoryError:
        raise
    except Exception as exc:
        raise ConversionError(f"The rule contains a value that cannot be read: {_first_line(exc)}.") from None
    if errors:
        raise ConversionError("This is not a complete Sigma rule. " + " ".join(f"{e}." for e in errors))
    return warnings


def normalize_pysigma_pipeline(pipeline_id: str) -> str:
    pipeline_id = (pipeline_id or "").strip().lower()
    legacy = {"sysmon_raw": "splunk_windows", "splunk_cim": "splunk_windows", "generic": "splunk_none",
              "none": "splunk_none"}
    pipeline_id = legacy.get(pipeline_id, pipeline_id)
    return pipeline_id if pipeline_id in PYSIGMA_PIPELINE_LABELS else DEFAULT_PIPELINE


def load_pysigma_pipeline(pipeline_id: str, warnings: List[str]) -> Any:
    pipeline_id = normalize_pysigma_pipeline(pipeline_id)
    if pipeline_id == "splunk_none":
        return None
    try:
        from sigma.pipelines.splunk import splunk_windows_pipeline
        return splunk_windows_pipeline()
    except MemoryError:
        raise
    except Exception:
        warnings.append(f"pySigma pipeline '{pipeline_id}' was not available. Conversion continued without this pipeline.")
        return None


def normalize_pysigma_output(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace").strip()
        except Exception:
            return str(value)
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            if isinstance(item, (dict, list)):
                out.append(json.dumps(item, indent=2, ensure_ascii=False))
            else:
                out.append(str(item))
        return "\n\n".join(x for x in out if x).strip()
    if isinstance(value, dict):
        return json.dumps(value, indent=2, ensure_ascii=False)
    return str(value).strip()


def pysigma_convert_collection(collection: Any, backend: Any, output_format: Optional[str] = None) -> str:
    if output_format:
        try:
            return normalize_pysigma_output(backend.convert(collection, output_format=output_format))
        except TypeError:
            return normalize_pysigma_output(backend.convert(collection, output_format))
    return normalize_pysigma_output(backend.convert(collection))


def _backend_errors(backend: Any) -> List[str]:
    """Messages pySigma collected instead of raising (collect_errors=True)."""
    messages = []
    for item in list(getattr(backend, "errors", None) or []):
        exc = item[1] if isinstance(item, tuple) and len(item) > 1 else item
        messages.append(f"{type(exc).__name__}: {_first_line(exc)}")
    return messages


def run_pysigma_conversion(data: Dict[str, Any], pipeline_id: str, warnings: List[str]) -> Dict[str, str]:
    """Convert the already-validated rule document (the same object the app checked, so both parsers agree)."""
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.splunk import SplunkBackend
    except MemoryError:
        raise
    except Exception as exc:
        raise ConverterUnavailable(
            "pySigma and the Splunk backend are not installed in this Python environment. "
            "Install the packages in requirements.txt (see the README) and restart the app.") from exc

    def collection_of() -> Any:
        try:
            collection = SigmaCollection.from_dicts([copy.deepcopy(data)])
        except MemoryError:
            raise
        except Exception as exc:
            raise ConversionError(f"pySigma could not parse this Sigma rule: {_first_line(exc)}") from exc
        problems = [f"{type(e).__name__}: {_first_line(e)}" for e in getattr(collection, "errors", None) or []]
        if problems:
            raise ConversionError("pySigma could not parse this Sigma rule: " + problems[0])
        return collection

    collection = collection_of()
    backend = SplunkBackend(processing_pipeline=load_pysigma_pipeline(pipeline_id, warnings), collect_errors=True)
    try:
        query = pysigma_convert_collection(collection, backend)
    except MemoryError:
        raise
    except Exception as exc:
        raise ConversionError(f"pySigma could not convert this rule: {_first_line(exc)}") from exc
    errors = _backend_errors(backend)
    if errors and not query:
        raise ConversionError("pySigma could not convert this rule: " + errors[0])
    warnings.extend(f"Conversion error: {message}" for message in errors)

    secondary = ""
    saved_backend = SplunkBackend(processing_pipeline=load_pysigma_pipeline(pipeline_id, []), collect_errors=True)
    try:
        # A fresh collection: the first pass already applied the pipeline to the rule objects.
        secondary = pysigma_convert_collection(collection_of(), saved_backend, "savedsearches")
    except MemoryError:
        raise
    except Exception as exc:
        warnings.append(f"Splunk savedsearches output was not generated by pySigma: {_first_line(exc)}")
    warnings.extend(f"savedsearches.conf: {message}" for message in _backend_errors(saved_backend))
    return {"query": query, "secondary_output": secondary}


def score_converted_rule(data: Dict[str, Any], query: str, warnings: List[str], errors: List[str]) -> Dict[str, Any]:
    score = 100
    notes: List[str] = []
    if errors:
        score -= 35
        notes.append("Fix validation errors before using this rule.")
    if not data.get("falsepositives"):
        score -= 10
        notes.append("Add false positive and tuning notes.")
    if not data.get("tags"):
        score -= 10
        notes.append("Add MITRE ATT&CK tags if applicable.")
    if "index=*" in query:
        score -= 15
        notes.append("Do not deploy Splunk rules with index=* in production.")
    if query.count("*") > 25:
        score -= 10
        notes.append("The converted query is wildcard-heavy; test performance and false positives.")
    if len(warnings) >= 3:
        score -= min(20, len(warnings) * 3)
    score = max(0, min(100, score))
    status = "Production Review" if score >= 80 and not errors else "Needs Tuning" if score >= 55 else "Needs Rework"
    base_notes = [
        "Confirm the selected pipeline matches your Splunk field names.",
        "Scope the search to your Sysmon index and source before scheduling it.",
        "Verify that all required fields are collected in your SIEM.",
        "Run against historical data before enabling alerting.",
    ]
    return {"score": score, "status": status, "notes": notes + base_notes}


def convert(content: str, pipeline_id: str) -> Dict[str, Any]:
    """Convert one Sigma rule to SPL. Raises ConversionError or ConverterUnavailable."""
    data = parse_rule_converter_source(content)
    pipeline_id = normalize_pysigma_pipeline(pipeline_id)
    warnings = validate_rule(data)
    conversion = run_pysigma_conversion(data, pipeline_id, warnings)
    query = conversion["query"]
    quality = score_converted_rule(data, query, warnings, [])
    return {
        "ok": True,
        "pipeline": pipeline_id,
        "pipeline_label": PYSIGMA_PIPELINE_LABELS[pipeline_id],
        "title": str(data.get("title") or "Converted Sigma rule"),
        "techniques": sorted(extract_techniques(data)),
        "required_fields": extract_sigma_required_fields(data),
        "spl": query,
        "savedsearches_conf": conversion["secondary_output"],
        "warnings": sorted(set(warnings)),
        "quality": quality,
    }


# ------------------------------------------------------------------------------------- isolated child
def _child_limits() -> None:
    """Apply each limit on its own, never above the current hard limit; report any that cannot be set."""
    try:
        import resource
    except ImportError:  # pragma: no cover - platform without resource limits
        sys.stderr.write("warning: resource limits are not available on this platform\n")
        return
    for name, value in (("RLIMIT_CPU", CHILD_LIMITS["cpu_seconds"]), ("RLIMIT_AS", CHILD_LIMITS["memory_bytes"])):
        try:
            which = getattr(resource, name)
            _soft, hard = resource.getrlimit(which)
            if hard != resource.RLIM_INFINITY:
                value = min(value, hard)
            resource.setrlimit(which, (value, hard if hard != resource.RLIM_INFINITY else value))
        except (ValueError, OSError, AttributeError) as exc:
            sys.stderr.write(f"warning: could not set {name}: {exc}\n")


def convert_isolated(content: str, pipeline_id: str) -> Dict[str, Any]:
    """``convert`` in a child process with CPU, memory and wall-clock limits.

    Cheap checks (size, YAML syntax, required keys) run here first so common
    mistakes get an immediate, readable answer.
    """
    validate_rule(parse_rule_converter_source(content))
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": root, "PYTHONDONTWRITEBYTECODE": "1",
           "LANG": "C.UTF-8", "HOME": os.environ.get("HOME", root)}
    payload = json.dumps({"content": content, "pipeline": pipeline_id}).encode("utf-8")
    timeout = CHILD_LIMITS["timeout_seconds"]
    try:
        proc = subprocess.run([sys.executable, "-m", "detection_toolkit.converter"], input=payload,
                              capture_output=True, cwd=root, env=env, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ConversionError(f"The conversion took longer than {timeout} s and was stopped. Simplify the rule, "
                              "for example by using fewer windash or base64offset modifiers.") from None
    except OSError as exc:
        raise ConverterFailure(f"The converter process could not start: {exc}") from None
    try:
        reply = json.loads(proc.stdout.decode("utf-8") or "{}")
    except ValueError:
        reply = {}
    if reply.get("ok"):
        return reply["result"]
    if reply.get("kind") == "conversion":
        raise ConversionError(reply.get("error") or "The rule could not be converted.")
    if reply.get("kind") == "unavailable":
        raise ConverterUnavailable(reply.get("error") or "pySigma is not available.")
    if proc.returncode < 0 or reply.get("kind") == "memory":
        raise ConversionError("The conversion reached its CPU or memory limit and was stopped. Simplify the rule, "
                              "for example by using fewer windash or base64offset modifiers.")
    logger.error("converter child failed (exit %s): %s %s", proc.returncode, reply.get("error", ""),
                 proc.stderr.decode("utf-8", errors="replace")[-2000:])
    raise ConverterFailure("The converter failed unexpectedly. The details are in the server log.")


def _main() -> int:
    _child_limits()
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        result = convert(str(payload.get("content") or ""), str(payload.get("pipeline") or DEFAULT_PIPELINE))
        sys.stdout.write(json.dumps({"ok": True, "result": result}, ensure_ascii=False, default=str))
        return 0
    except ConversionError as exc:
        if _caused_by_memory_error(exc):
            sys.stdout.write(json.dumps({"ok": False, "kind": "memory"}))
            return 3
        sys.stdout.write(json.dumps({"ok": False, "kind": "conversion", "error": str(exc)}))
        return 0
    except ConverterUnavailable as exc:
        sys.stdout.write(json.dumps({"ok": False, "kind": "unavailable", "error": str(exc)}))
        return 0
    except MemoryError:
        sys.stdout.write(json.dumps({"ok": False, "kind": "memory"}))
        return 3
    except Exception as exc:
        if _caused_by_memory_error(exc):
            sys.stdout.write(json.dumps({"ok": False, "kind": "memory"}))
            return 3
        sys.stdout.write(json.dumps({"ok": False, "kind": "error", "error": f"{type(exc).__name__}: {_first_line(exc)}"}))
        return 2


def _caused_by_memory_error(exc: BaseException) -> bool:
    seen = 0
    while exc is not None and seen < 20:
        if isinstance(exc, MemoryError):
            return True
        exc = exc.__cause__ or exc.__context__
        seen += 1
    return False


if __name__ == "__main__":
    sys.exit(_main())
