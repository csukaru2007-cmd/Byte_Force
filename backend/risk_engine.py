"""Unified, explainable review-priority score.

The score ranks how urgently a project deserves human review. It is computed from the
findings with fixed, published weights; it is NOT a probability of malware and it is
never derived from a single benign signal (INFO findings carry 0 points).

    points(finding) = SEVERITY_POINTS[severity] x CONFIDENCE_FACTOR[confidence]

* identical findings were already removed by dedupe_findings()
* findings of the same category on the same file+line describe one issue: only the
  highest-scoring one counts (e.g. EXEC002 and EXEC003 on the same cast)
* repeats of the same rule count REPEAT_SHARE of their points, at most MAX_REPEATS times
* the total is capped at 100
"""

from __future__ import annotations

from collections import defaultdict

from backend.models import COMPONENTS, Finding, ScanIssue, severity_rank

SEVERITY_POINTS = {"INFO": 0, "LOW": 2, "MEDIUM": 6, "HIGH": 15, "CRITICAL": 30}
CONFIDENCE_FACTOR = {"DEFINITE": 1.0, "INDICATOR": 0.8, "UNRESOLVED": 0.0}
REPEAT_SHARE = 0.25
MAX_REPEATS = 4
BANDS = [(0, "NONE"), (1, "LOW"), (10, "MEDIUM"), (30, "HIGH"), (60, "CRITICAL")]
STATEMENT = ("Deterministic review-priority score computed from the findings listed below with fixed weights. "
             "It is not a probability that the project is malicious, and a low score does not prove the project is safe.")


def _band(score: float) -> str:
    level = "NONE"
    for threshold, name in BANDS:
        if score >= threshold:
            level = name
    return level


def _points(finding: Finding) -> float:
    return SEVERITY_POINTS[finding.severity] * CONFIDENCE_FACTOR[finding.confidence]


def assess_risk(findings: list[Finding], issues: list[ScanIssue], *, hardware_status: str,
                registry_available: bool, files_parsed: int) -> dict:
    # 1. one issue per (category, file, line): keep the strongest finding
    strongest: dict[tuple, Finding] = {}
    merged: dict[tuple, list[str]] = defaultdict(list)
    for finding in findings:
        if finding.line is None:
            key = ("unique", id(finding))
        else:
            key = (finding.category, finding.file, finding.line)
        merged[key].append(finding.rule_id)
        current = strongest.get(key)
        if current is None or _points(finding) > _points(current):
            strongest[key] = finding

    # 2. per-rule diminishing repeats
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for finding in strongest.values():
        by_rule[finding.rule_id].append(finding)

    contributions = []
    component_scores = {c: 0.0 for c in COMPONENTS}
    total = 0.0
    for rule_id, group in by_rule.items():
        group.sort(key=_points, reverse=True)
        first = _points(group[0])
        repeats = group[1:1 + MAX_REPEATS]
        points = first + sum(_points(f) * REPEAT_SHARE for f in repeats)
        if points <= 0:
            continue
        total += points
        component_scores[group[0].component] += points
        contributions.append({
            "rule_id": rule_id, "component": group[0].component, "category": group[0].category,
            "severity": group[0].severity, "confidence": group[0].confidence,
            "description": group[0].description, "findings": len(group),
            "counted": 1 + len(repeats), "points": round(points, 1),
            "formula": f"{SEVERITY_POINTS[group[0].severity]} x {CONFIDENCE_FACTOR[group[0].confidence]}"
                       + (f" + {len(repeats)} repeat(s) x {REPEAT_SHARE:.0%}" if repeats else ""),
        })
    contributions.sort(key=lambda c: (-c["points"], c["rule_id"]))
    score = min(100, round(total))

    merged_notes = [{"location": f"{k[1]}:{k[2]}", "category": k[0], "rules": v}
                    for k, v in merged.items() if k[0] != "unique" and len(v) > 1]

    incomplete = []
    if not registry_available:
        incomplete.append("PlatformIO Registry metadata was unavailable for some dependencies.")
    if hardware_status == "skipped":
        incomplete.append("Hardware checks were skipped (no usable chip profile).")
    elif hardware_status == "completed_with_profile_mismatch":
        incomplete.append("The selected chip profile does not match the project's board.")
    if files_parsed == 0:
        incomplete.append("No source file was parsed.")
    parser_problems = [i for i in issues if i.stage == "parser"]
    if parser_problems:
        incomplete.append(f"{len(parser_problems)} parser issue(s): some code may not have been analysed.")
    if any(i.stage == "security" and i.level == "ERROR" for i in issues):
        incomplete.append("A security detector failed.")

    counts = defaultdict(int)
    for finding in findings:
        counts[finding.severity] += 1
    highest = max((f.severity for f in findings), key=severity_rank, default=None)
    return {
        "score": score,
        "review_priority": _band(score),
        "statement": STATEMENT,
        "highest_severity": highest,
        "findings_by_severity": {s: counts.get(s, 0) for s in SEVERITY_POINTS},
        "component_scores": {c: min(100, round(v)) for c, v in component_scores.items()},
        "contributions": contributions,
        "merged_locations": merged_notes,
        "completeness": "PARTIAL" if incomplete else "COMPLETE",
        "incomplete_reasons": incomplete,
        "method": {"severity_points": SEVERITY_POINTS, "confidence_factor": CONFIDENCE_FACTOR,
                   "repeat_share": REPEAT_SHARE, "max_repeats_counted": MAX_REPEATS,
                   "bands": {name: threshold for threshold, name in BANDS}, "cap": 100},
    }
