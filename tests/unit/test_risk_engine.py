from backend.models import Finding, ScanIssue
from backend.risk_engine import assess_risk


def f(rule, severity, confidence="INDICATOR", line=1, category="X", component="security_engine", file="a.cpp"):
    return Finding(component=component, rule_id=rule, category=category, severity=severity, description=rule,
                   file=file, line=line, confidence=confidence)


def _assess(findings, issues=(), **kw):
    defaults = dict(hardware_status="completed", registry_available=True, files_parsed=1)
    defaults.update(kw)
    return assess_risk(findings, list(issues), **defaults)


def test_info_findings_score_zero():
    risk = _assess([f("NET001", "INFO", line=i) for i in range(20)])
    assert risk["score"] == 0 and risk["review_priority"] == "NONE" and risk["contributions"] == []
    assert "not a probability" in risk["statement"]


def test_weights_and_explanation():
    risk = _assess([f("HW001", "HIGH", "DEFINITE", category="HW"), f("CRED001", "MEDIUM", line=5)])
    assert risk["score"] == round(15 * 1.0 + 6 * 0.8)
    assert [c["rule_id"] for c in risk["contributions"]] == ["HW001", "CRED001"]
    assert risk["contributions"][0]["formula"] == "15 x 1.0"


def test_repeats_are_diminishing_and_capped():
    risk = _assess([f("HW001", "HIGH", "DEFINITE", line=i, category="HW") for i in range(10)])
    contribution = risk["contributions"][0]
    assert contribution["findings"] == 10 and contribution["counted"] == 5
    assert contribution["points"] == 15 + 4 * 15 * 0.25


def test_same_location_same_category_counted_once():
    risk = _assess([f("EXEC003", "HIGH", line=12, category="DYNAMIC_EXECUTION"),
                    f("EXEC002", "HIGH", line=12, category="DYNAMIC_EXECUTION")])
    assert risk["score"] == 12
    assert risk["merged_locations"][0]["rules"] == ["EXEC003", "EXEC002"]


def test_unresolved_findings_do_not_score():
    assert _assess([f("HW012", "INFO", "UNRESOLVED")])["score"] == 0


def test_score_cap_and_bands():
    risk = _assess([f(f"R{i}", "CRITICAL", "DEFINITE", line=i) for i in range(10)])
    assert risk["score"] == 100 and risk["review_priority"] == "CRITICAL"
    assert _assess([f("A", "LOW")])["review_priority"] == "LOW"


def test_incomplete_scans_are_flagged():
    risk = _assess([], [ScanIssue("parser", "x", level="WARNING")], hardware_status="skipped",
                   registry_available=False, files_parsed=0)
    assert risk["completeness"] == "PARTIAL" and len(risk["incomplete_reasons"]) == 4
    assert _assess([])["completeness"] == "COMPLETE"


def test_component_scores_are_separate():
    risk = _assess([f("PKG002", "HIGH", component="platformio_intelligence", category="P"),
                    f("HW001", "HIGH", "DEFINITE", component="hardware_intelligence", category="H")])
    assert risk["component_scores"] == {"platformio_intelligence": 12, "hardware_intelligence": 15,
                                        "security_engine": 0}
