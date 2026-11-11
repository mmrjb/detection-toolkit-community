import yaml

from detection_toolkit import telemetry
from detection_toolkit.db import connect
from detection_toolkit.rules import get_rule

from conftest import POWERSHELL_RULE


def test_exact_matching_does_not_confuse_event_ids():
    item = {"data_source": "Windows Sysmon EID 10", "aliases": "Sysmon Event ID 10; Sysmon process access"}
    assert not telemetry.data_source_matches("Windows Sysmon EID 1", item)
    assert telemetry.data_source_matches("windows sysmon eid 10", item)
    assert telemetry.data_source_matches("Sysmon process access", item)


def test_log_type_is_not_a_match():
    item = {"data_source": "Windows Sysmon EID 10", "aliases": "", "log_type": "Process Access"}
    assert not telemetry.data_source_matches("EDR Process Access", item)


def test_powershell_technique_guidance_is_low_in_demo(app):
    with connect(app.config["DTK_DB_PATH"]) as conn:
        result = telemetry.technique_feasibility(conn, "T1059.001")
    assert result["feasibility"] == "Low"
    assert "PowerShell 4104" in result["missing_sources"]
    assert "Windows Sysmon EID 1" in result["available_sources"]


def test_powershell_rule_is_ready_on_sysmon_eid_1(app):
    with connect(app.config["DTK_DB_PATH"]) as conn:
        rule = get_rule(conn, POWERSHELL_RULE)
        req = telemetry.rule_requirements(conn, rule, yaml.safe_load(rule["raw_yaml"]))
    assert req["fields"] == ["CommandLine", "Image", "OriginalFileName"]
    by_key = {e["key"]: e for e in req["event_types"]}
    assert by_key["sysmon_1"]["readiness"] == "ready"
    assert by_key["security_4688"]["readiness"] == "partial"
    assert req["readiness"] == "ready"
