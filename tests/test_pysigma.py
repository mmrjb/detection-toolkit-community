"""Conversion and the local sample check need pySigma; they are skipped without it."""
import json

import pytest

pytest.importorskip("sigma.backends.splunk")

from detection_toolkit import converter, sigma_eval  # noqa: E402
from detection_toolkit.config import SEED_DIR  # noqa: E402

RULE = (SEED_DIR / "rules" / "win_proc_creation_powershell_encoded_command.yml").read_text(encoding="utf-8")


def test_demo_rule_converts_to_spl():
    result = converter.convert(RULE, "splunk_windows")
    spl = result["spl"]
    assert spl
    assert "CommandLine" in spl and "EncodedCommand" in spl
    assert "Image" in spl and "OriginalFileName" in spl


def test_incomplete_rule_is_rejected_readably():
    with pytest.raises(converter.ConversionError, match="Missing required Sigma field: detection"):
        converter.convert("title: x\nlogsource:\n  product: windows\n", "splunk_windows")


def test_demo_events_behave_as_documented():
    seed = json.loads((SEED_DIR / "demo_events.json").read_text(encoding="utf-8"))
    payload = {"rule_text": RULE, "events": [e["event"] for e in seed["events"]],
               "expectations": [e["expectation"] for e in seed["events"]],
               "labels": [e["label"] for e in seed["events"]]}
    result = sigma_eval.run_isolated(payload)
    assert result["outcome"] == "passed", result["reasons"]
    assert [e["matched"] for e in result["events"]] == [True, False]


def test_isolated_conversion_matches_in_process():
    assert converter.convert_isolated(RULE, "splunk_windows")["spl"] == converter.convert(RULE, "splunk_windows")["spl"]


def test_yaml_aliases_are_refused():
    with pytest.raises(converter.ConversionError, match="aliases"):
        converter.parse_rule_converter_source("a: &x [1, 2]\nb: *x\n")


def test_converter_keeps_the_rule_for_crlf_posts(client, csrf):
    from conftest import POWERSHELL_RULE
    form = {"csrf_token": csrf, "rule": POWERSHELL_RULE, "technique": "T1059.001",
            "sigma_yaml": RULE.replace("\n", "\r\n"), "pipeline": "splunk_windows"}
    html = client.post("/converter", data=form).get_data(as_text=True)
    assert "Copy SPL" in html
    assert f"rule={POWERSHELL_RULE}" in html.split("Add to Rule Plan")[0].rsplit("href=", 1)[-1]
