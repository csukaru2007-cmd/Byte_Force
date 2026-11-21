"""Central upload decision: combines the main security engine with the ML prediction.

    GREEN  READY TO UPLOAD   main engine GREEN (complete, no blocking or review findings) AND ML GREEN
    YELLOW REVIEW REQUIRED   unresolved/suspicious findings, incomplete analysis, ML unavailable,
                             or the two systems disagree
    RED    UPLOAD BLOCKED    main engine confirms a HIGH/CRITICAL finding (ML can never override this),
                             or ML predicts RED while the main engine also reports review findings

The backend enforces the decision (POST /api/scan/{id}/upload returns 403 unless GREEN).
"""

from __future__ import annotations

BLOCKING = ("HIGH", "CRITICAL")
TEXT = {"GREEN": "READY TO UPLOAD", "YELLOW": "REVIEW REQUIRED", "RED": "UPLOAD BLOCKED"}


def main_engine_decision(findings: list[dict], risk: dict | None, completed: bool) -> dict:
    """GREEN / YELLOW / RED from the deterministic engine alone, with reasons."""
    if not completed or risk is None:
        return {"status": "YELLOW", "complete": False, "reasons": ["Main security analysis did not complete."],
                "blocking_findings": []}
    blocking = [f for f in findings if f["severity"] in BLOCKING and f["confidence"] != "UNRESOLVED"]
    review = [f for f in findings if f["severity"] == "MEDIUM"
              or (f["severity"] in BLOCKING and f["confidence"] == "UNRESOLVED")]
    reasons = []
    if blocking:
        reasons.append(f"{len(blocking)} confirmed HIGH/CRITICAL finding(s): "
                       + ", ".join(sorted({f['rule_id'] for f in blocking})))
        status = "RED"
    elif review:
        reasons.append(f"{len(review)} finding(s) need human review: "
                       + ", ".join(sorted({f['rule_id'] for f in review})))
        status = "YELLOW"
    else:
        status = "GREEN"
    complete = risk.get("completeness") == "COMPLETE"
    if not complete:
        reasons += [f"Analysis incomplete: {r}" for r in risk.get("incomplete_reasons", [])]
        if status == "GREEN":
            status = "YELLOW"
    if status == "GREEN":
        reasons.append("Analysis complete; no MEDIUM, HIGH or CRITICAL findings.")
    return {"status": status, "complete": complete, "reasons": reasons,
            "blocking_findings": [{k: f.get(k) for k in ("rule_id", "severity", "file", "line", "description")}
                                  for f in blocking]}


def final_decision(main: dict, ml: dict) -> dict:
    ml_label = ml.get("label") if ml.get("status") == "ok" else None
    m = main["status"]
    reasons = []
    if m == "RED":
        status = "RED"
        reasons.append("Main security engine found a blocking vulnerability; the ML prediction cannot override it.")
    elif ml_label is None:
        status = "YELLOW"
        reasons.append("ML prediction unavailable" + (f" ({ml.get('reason')})" if ml.get("reason") else "")
                       + "; GREEN requires both systems.")
    elif ml_label == "RED":
        if m == "YELLOW":
            status = "RED"
            reasons.append("ML predicts RED and the main engine reports unresolved findings: upload blocked.")
        else:
            status = "YELLOW"
            reasons.append("ML predicts RED but the main engine found no blocking issue: systems disagree, "
                           "human review required.")
    elif m == "GREEN" and ml_label == "GREEN":
        status = "GREEN"
        reasons.append("Main engine and ML both report GREEN.")
    else:
        status = "YELLOW"
        if m != ml_label:
            reasons.append(f"Main engine says {m}, ML says {ml_label}: systems disagree, human review required.")
        else:
            reasons.append("Both systems report unresolved or suspicious behaviour: human review required.")
    return {"status": status, "text": TEXT[status], "upload_allowed": status == "GREEN",
            "main_engine": m, "ml": ml_label, "reasons": reasons + main["reasons"]}
