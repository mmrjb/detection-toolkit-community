from detection_toolkit import gaps, plans
from detection_toolkit.db import connect

from conftest import POWERSHELL_RULE


def test_powershell_is_the_top_work_item(app):
    with connect(app.config["DTK_DB_PATH"]) as conn:
        snapshot = gaps.build(conn)
    top = snapshot["top"][0]
    assert top["technique"] == "T1059.001"
    assert top["report_count"] == 2 and top["points"] == 20
    assert any(e["family"] == "T1053" and e["reason"] == "reserved" for e in snapshot["excluded"])


def test_a_plan_reserves_the_family(app):
    with connect(app.config["DTK_DB_PATH"]) as conn:
        values, errors = plans.validate(conn, {"technique": "T1059.001", "rule": POWERSHELL_RULE,
                                               "status": "planned", "validation_status": "not_assessed"})
        assert not errors
        plans.create(conn, values)
        snapshot = gaps.build(conn)
    assert all(c["family"] != "T1059" for c in snapshot["candidates"])
    assert any(e["family"] == "T1059" and e["reason"] == "reserved" for e in snapshot["excluded"])
