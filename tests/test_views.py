from conftest import POWERSHELL_RULE

PAGES = ["/gaps", "/coverage", "/rules", "/data-sources", "/converter", "/plans", "/plans/new", "/plans/1"]


def test_every_view_renders(client):
    for path in PAGES:
        response = client.get(path)
        assert response.status_code == 200, path
        assert "Content-Security-Policy" in response.headers


def test_root_opens_gap_prioritization(client):
    response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/gaps")


def test_selection_is_carried_into_navigation(client):
    html = client.get(f"/rules?technique=T1059.001&rule={POWERSHELL_RULE}").get_data(as_text=True)
    assert f'href="/converter?technique=T1059.001&amp;rule={POWERSHELL_RULE}"' in html
    assert "PowerShell Launched With an Encoded Command" in html
    assert "CC0-1.0" in html


def test_rule_search_filters_by_log_source(client):
    html = client.get("/rules?category=registry_set").get_data(as_text=True)
    assert "Run Key Value Pointing" in html
    assert "PowerShell Launched" not in html


def test_post_without_csrf_token_is_blocked(client):
    response = client.post("/plans", data={"technique": "T1059.001"})
    assert response.status_code == 403


def test_create_then_reopen_plan(client, csrf):
    form = {"csrf_token": csrf, "technique": "T1059.001", "rule": POWERSHELL_RULE, "title": "",
            "status": "planned", "validation_status": "implementable", "priority": "High", "origin": "gaps",
            "telemetry": "Windows Sysmon EID 1: Image, OriginalFileName, CommandLine"}
    first = client.post("/plans", data=form)
    assert first.status_code == 302 and "/plans/2" in first.headers["Location"]
    second = client.post("/plans", data=form)
    assert second.status_code == 302 and "/plans/2" in second.headers["Location"]
    page = client.get(first.headers["Location"]).get_data(as_text=True)
    assert "Plan #2" in page


def test_validated_plan_needs_evidence(client, csrf):
    form = {"csrf_token": csrf, "technique": "T1059.001", "rule": POWERSHELL_RULE,
            "status": "in_progress", "validation_status": "validated", "telemetry": "Sysmon EID 1"}
    response = client.post("/plans", data=form)
    assert response.status_code == 400
    assert "Describe the lab evidence" in response.get_data(as_text=True)


def test_converter_reports_yaml_errors(client, csrf):
    response = client.post("/converter", data={"csrf_token": csrf, "sigma_yaml": "title: [unclosed", "pipeline": "splunk_windows"})
    assert response.status_code == 400
    assert "YAML syntax error" in response.get_data(as_text=True)
