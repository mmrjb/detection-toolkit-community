"""The six views. Every page reads the shared selection (?technique=...&rule=...)
and every cross-view link carries it through ``ctx_url``."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

import yaml
from flask import Blueprint, abort, flash, g, jsonify, redirect, render_template, request, url_for

from . import attack, converter, coverage, gaps, plans, rules, sigma_eval, telemetry
from .config import APP_VERSION
from .db import db, schema_state

bp = Blueprint("main", __name__)


# ------------------------------------------------------------------------------------- shared context
def load_selection() -> None:
    """Validated selection from the query string or a submitted form (called before each request)."""
    values = request.values
    technique = attack.technique_param(values.get("technique"))
    rule_uid = rules.uid_param(values.get("rule"))
    selection: Dict[str, Any] = {"technique": technique, "technique_name": attack.technique_name(technique or ""),
                                 "rule": None, "rule_title": None}
    if rule_uid:
        with db() as conn:
            title = rules.rule_title(conn, rule_uid)
        if title:
            selection.update(rule=rule_uid, rule_title=title)
    g.selection = selection


def ctx_url(endpoint: str, **params: Any) -> str:
    """url_for that keeps the selected technique and rule; pass a parameter as None or '' to drop it."""
    selection = getattr(g, "selection", None) or {}
    args: Dict[str, Any] = {}
    if selection.get("technique"):
        args["technique"] = selection["technique"]
    if selection.get("rule"):
        args["rule"] = selection["rule"]
    for key, value in params.items():
        if value is None or value == "" or value is False:
            args.pop(key, None)
        else:
            args[key] = value
    return url_for(endpoint, **args)


def _selected_technique() -> Optional[str]:
    return (getattr(g, "selection", None) or {}).get("technique")


def _selected_rule() -> Optional[str]:
    return (getattr(g, "selection", None) or {}).get("rule")


def _rule_data(rule: Dict[str, Any]) -> Dict[str, Any]:
    data = yaml.safe_load(rule["raw_yaml"])
    return data if isinstance(data, dict) else {}


# ------------------------------------------------------------------------------------------- routes
@bp.route("/")
def index():
    return redirect(ctx_url("main.gaps_view"))


@bp.route("/healthz")
def healthz():
    from flask import current_app
    state = schema_state(current_app.config["DTK_DB_PATH"])
    return jsonify({"status": "ok" if state == "ok" else "not_initialized", "schema": state,
                    "version": APP_VERSION}), (200 if state == "ok" else 503)


@bp.route("/gaps")
def gaps_view():
    technique = _selected_technique()
    with db() as conn:
        snapshot = gaps.build(conn)
        focus = technique or (snapshot["top"][0]["technique"] if snapshot["top"] else None)
        detail = gaps.detail(conn, snapshot, focus)
    return render_template("gaps.html", snapshot=snapshot, detail=detail, focus=focus,
                           focus_is_selection=bool(technique), view="gaps")


@bp.route("/coverage")
def coverage_view():
    tactic = str(request.args.get("tactic") or "").strip().lower()
    state = str(request.args.get("state") or "all").strip()
    if state not in coverage.STATE_FILTERS:
        state = "all"
    with db() as conn:
        data = coverage.build(conn, tactic=tactic or None, state=state, selected=_selected_technique())
    if tactic not in dict(data["tactics"]):
        tactic = ""
    return render_template("coverage.html", data=data, tactic=tactic, state=state,
                           state_filters=coverage.STATE_FILTERS, view="coverage")


@bp.route("/rules")
def rules_view():
    query, errors = rules.parse_query(request.args)
    with db() as conn:
        result = rules.search(conn, query)
        facets = rules.facets(conn)
        sources = rules.source_names(conn)
        selected = rules.get_rule(conn, _selected_rule())
    return render_template("rules.html", query=query, errors=errors, result=result, facets=facets,
                           sources=sources, selected=selected, link_args=rules.link_args(query), view="rules")


def _data_sources_page(check: Optional[Dict[str, Any]] = None, check_error: Optional[str] = None, status: int = 200):
    technique = _selected_technique()
    with db() as conn:
        choices = rules.rule_choices(conn)
        rule = rules.get_rule(conn, _selected_rule())
        inventory = telemetry.load_inventory(conn)
        requirements = telemetry.rule_requirements(conn, rule, _rule_data(rule), inventory) if rule else None
        guidance_ids = [technique] if technique else (rule["techniques"] if rule else [])
        memo: Dict[str, Any] = {}
        guidance = [telemetry.technique_feasibility(conn, t, inventory, memo) for t in guidance_ids]
        events = []
        if rule:
            for row in conn.execute("SELECT * FROM demo_events WHERE rule_uid = ? ORDER BY id", (rule["uid"],)):
                events.append({"id": row["id"], "label": row["label"], "expectation": row["expectation"],
                               "explanation": row["explanation"], "event_type": row["event_type"],
                               "event": json.loads(row["event_json"])})
    return render_template("data_sources.html", choices=choices, rule=rule, requirements=requirements,
                           guidance=guidance, inventory=inventory,
                           inventory_summary=telemetry.inventory_status_summary(inventory), events=events,
                           check=check, check_error=check_error, view="data_sources"), status


@bp.route("/data-sources")
def data_sources_view():
    return _data_sources_page()


@bp.route("/data-sources/check", methods=["POST"])
def data_sources_check():
    rule_uid = _selected_rule()
    if not rule_uid:
        return _data_sources_page(check_error="Select a rule before running the sample check.", status=400)
    with db() as conn:
        rule = rules.get_rule(conn, rule_uid)
        rows = conn.execute("SELECT label, expectation, event_json FROM demo_events WHERE rule_uid = ? ORDER BY id",
                            (rule_uid,)).fetchall()
    if not rows:
        return _data_sources_page(check_error="This rule has no bundled demo events to check.", status=400)
    payload = {"rule_text": rule["raw_yaml"], "events": [json.loads(r["event_json"]) for r in rows],
               "expectations": [r["expectation"] for r in rows], "labels": [r["label"] for r in rows]}
    try:
        result = sigma_eval.run_isolated(payload)
    except sigma_eval.ValidationInputError as exc:
        return _data_sources_page(check_error=str(exc), status=400)
    except RuntimeError as exc:
        return _data_sources_page(check_error=f"{exc}. Check that pySigma is installed (see the README).", status=503)
    return _data_sources_page(check=result)


# ----------------------------------------------------------------------------------------- rule plans
def _plan_form_context(conn, form: Dict[str, Any]) -> Dict[str, Any]:
    return {"form": form, "rule_choices": rules.rule_choices(conn), "statuses": plans.STATUSES,
            "validation_statuses": plans.VALIDATION_STATUSES, "priorities": plans.PRIORITIES,
            "techniques": [t for t in attack.catalog()["techniques"] if attack.is_active(t["id"])]}


@bp.route("/plans")
def plans_view():
    status = str(request.args.get("status") or "").strip()
    with db() as conn:
        items = plans.list_plans(conn, technique=_selected_technique(), status=status or None)
        counts = plans.status_counts(conn)
    return render_template("plans.html", items=items, counts=counts, status=status if status in plans.STATUSES else "",
                           statuses=plans.STATUSES, view="plans")


@bp.route("/plans/new")
def plan_new():
    technique = _selected_technique() or ""
    rule_uid = _selected_rule()
    origin = str(request.args.get("origin") or "manual")
    with db() as conn:
        rule = rules.get_rule(conn, rule_uid)
        if rule and not technique and rule["techniques"]:
            technique = rule["techniques"][0]
        telemetry_text, notes, priority = "", "", "Medium"
        if rule:
            telemetry_text = telemetry.telemetry_lines(telemetry.rule_requirements(conn, rule, _rule_data(rule)))
        if origin == "gaps" and technique:
            snapshot = gaps.build(conn)
            candidate = next((c for c in snapshot["candidates"] if c["technique"] == technique), None)
            if candidate:
                notes = "From Gap Prioritization:\n" + "\n".join(f"- {reason}" for reason in candidate["reasons"])
                priority = "High" if candidate["position"] <= 3 else "Medium"
        form = plans.blank_form(technique=technique, rule_uid=rule["uid"] if rule else None,
                                title=rule["title"] if rule else "", telemetry=telemetry_text, notes=notes,
                                origin=origin, priority=priority)
        existing = plans.find_by_key(conn, plans.source_key(technique, form["rule_uid"])) if technique else None
        context = _plan_form_context(conn, form)
    return render_template("plan_form.html", plan=None, errors={}, existing=existing, view="plans", **context)


@bp.route("/plans", methods=["POST"])
def plan_create():
    with db() as conn:
        values, errors = plans.validate(conn, request.form)
        if errors:
            context = _plan_form_context(conn, values)
            return render_template("plan_form.html", plan=None, errors=errors, existing=None, view="plans",
                                   **context), 400
        plan_id, created = plans.create(conn, values)
    if created:
        flash(f"Plan #{plan_id} created.", "success")
    else:
        flash(f"A plan for this rule or technique already exists. Reopened plan #{plan_id}; "
              "the values you entered were not saved.", "warning")
    return redirect(ctx_url("main.plan_detail", plan_id=plan_id, technique=values["technique"],
                            rule=values["rule_uid"]))


@bp.route("/plans/<int:plan_id>")
def plan_detail(plan_id: int):
    with db() as conn:
        plan = plans.get(conn, plan_id)
        if plan is None:
            abort(404)
        context = _plan_form_context(conn, plan)
    return render_template("plan_form.html", plan=plan, errors={}, existing=None, view="plans", **context)


@bp.route("/plans/<int:plan_id>", methods=["POST"])
def plan_update(plan_id: int):
    with db() as conn:
        plan = plans.get(conn, plan_id)
        if plan is None:
            abort(404)
        values, errors = plans.validate(conn, request.form)
        conflict = None
        if not errors:
            saved, conflict = plans.update(conn, plan_id, values, str(request.form.get("expected_updated_at") or ""))
            if saved:
                flash(f"Plan #{plan_id} saved.", "success")
                return redirect(ctx_url("main.plan_detail", plan_id=plan_id, technique=values["technique"],
                                        rule=values["rule_uid"]))
        form = dict(plan, **values)
        context = _plan_form_context(conn, form)
    token = str(request.form.get("expected_updated_at") or plan["updated_at"])
    return render_template("plan_form.html", plan=plan, errors=errors, conflict=conflict, existing=None,
                           expected_updated_at=token, view="plans", **context), (409 if conflict else 400)


# ------------------------------------------------------------------------------------------ converter
@bp.route("/converter", methods=["GET", "POST"])
def converter_view():
    rule_uid = _selected_rule()
    with db() as conn:
        rule = rules.get_rule(conn, rule_uid)
        choices = rules.rule_choices(conn)
    pipeline = converter.normalize_pysigma_pipeline(str(request.values.get("pipeline") or converter.DEFAULT_PIPELINE))
    result, error, status = None, None, 200
    if request.method == "POST":
        content = converter.normalize_newlines(str(request.form.get("sigma_yaml") or ""))
        try:
            result = converter.convert_isolated(content, pipeline)
        except converter.ConversionError as exc:
            error, status = str(exc), 400
        except converter.ConverterUnavailable as exc:
            error, status = str(exc), 503
        except converter.ConverterFailure as exc:
            error, status = str(exc), 500
    else:
        content = rule["raw_yaml"] if rule else ""
    edited = bool(rule and content.strip() != rule["raw_yaml"].strip())
    techniques = (result or {}).get("techniques") or (rule["techniques"] if rule else [])
    return render_template("converter.html", rule=rule, choices=choices, content=content, pipeline=pipeline,
                           pipelines=converter.PYSIGMA_PIPELINE_LABELS, result=result, error=error, edited=edited,
                           plan_technique=_selected_technique() or (techniques[0] if techniques else None),
                           view="converter"), status
