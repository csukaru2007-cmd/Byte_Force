"""Central upload decision: every GREEN/YELLOW/RED path, ML unavailable, analysis failure."""

import pytest

from backend.decision import final_decision, main_engine_decision

COMPLETE = {"completeness": "COMPLETE", "incomplete_reasons": []}
PARTIAL = {"completeness": "PARTIAL", "incomplete_reasons": ["Registry metadata unavailable."]}


def f(severity, confidence="DEFINITE", rule="R1"):
    return {"rule_id": rule, "severity": severity, "confidence": confidence, "file": "src/main.cpp", "line": 1,
            "description": "x"}


def ml(label):
    return {"status": "ok", "label": label, "probabilities": {}}


ML_DOWN = {"status": "unavailable", "label": None, "reason": "model missing"}


def test_main_engine_levels():
    assert main_engine_decision([], COMPLETE, True)["status"] == "GREEN"
    assert main_engine_decision([f("LOW"), f("INFO")], COMPLETE, True)["status"] == "GREEN"
    assert main_engine_decision([f("MEDIUM")], COMPLETE, True)["status"] == "YELLOW"
    assert main_engine_decision([f("HIGH", "UNRESOLVED")], COMPLETE, True)["status"] == "YELLOW"
    assert main_engine_decision([f("HIGH")], COMPLETE, True)["status"] == "RED"
    assert main_engine_decision([f("CRITICAL", "INDICATOR")], COMPLETE, True)["status"] == "RED"
    assert main_engine_decision([], PARTIAL, True)["status"] == "YELLOW"      # incomplete never GREEN
    assert main_engine_decision([], None, False)["status"] == "YELLOW"        # failed analysis


def test_green_only_when_both_agree():
    main = main_engine_decision([], COMPLETE, True)
    d = final_decision(main, ml("GREEN"))
    assert d["status"] == "GREEN" and d["upload_allowed"] and d["text"] == "READY TO UPLOAD"
    assert final_decision(main, ml("YELLOW"))["status"] == "YELLOW"


@pytest.mark.parametrize("ml_result", [ml("GREEN"), ml("YELLOW"), ml("RED"), ML_DOWN])
def test_critical_finding_cannot_be_overridden_by_ml(ml_result):
    main = main_engine_decision([f("CRITICAL")], COMPLETE, True)
    d = final_decision(main, ml_result)
    assert d["status"] == "RED" and not d["upload_allowed"] and d["text"] == "UPLOAD BLOCKED"


def test_ml_red_escalates():
    assert final_decision(main_engine_decision([], COMPLETE, True), ml("RED"))["status"] == "YELLOW"
    assert final_decision(main_engine_decision([f("MEDIUM")], COMPLETE, True), ml("RED"))["status"] == "RED"


def test_disagreement_requires_review():
    d = final_decision(main_engine_decision([f("MEDIUM")], COMPLETE, True), ml("GREEN"))
    assert d["status"] == "YELLOW" and "disagree" in d["reasons"][0]


def test_ml_unavailable_or_analysis_failed_never_green():
    assert final_decision(main_engine_decision([], COMPLETE, True), ML_DOWN)["status"] == "YELLOW"
    assert final_decision(main_engine_decision([], PARTIAL, True), ml("GREEN"))["status"] == "YELLOW"
    failed = final_decision(main_engine_decision([], None, False), ml("GREEN"))
    assert failed["status"] == "YELLOW" and not failed["upload_allowed"]
