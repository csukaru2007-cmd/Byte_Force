"""Run the five security detectors over the extracted AST features."""

from __future__ import annotations

import json
import traceback
from collections import Counter
from pathlib import Path

from backend.ast_engine.ast_extractor import ProjectFeatures
from backend.models import Finding, ScanIssue, dedupe_findings
from backend.security_engine import (credential_detector, execution_detector, firmware_detector,
                                     network_detector, obfuscation_detector)
from backend.security_engine.base import DetectionContext, build_purposes, redact

DETECTORS = [
    ("network", network_detector.detect),
    ("credentials", credential_detector.detect),
    ("execution", execution_detector.detect),
    ("firmware", firmware_detector.detect),
    ("obfuscation", obfuscation_detector.detect),
]


def scrub(finding: Finding, secrets: set[str]) -> Finding:
    """Mask every known secret value anywhere in a finding (evidence, text and details)."""
    if not secrets:
        return finding
    ordered = sorted(secrets, key=len, reverse=True)

    def clean(text: str) -> str:
        for secret in ordered:
            if secret and secret in text:
                text = text.replace(secret, redact(secret).split(" ")[0])
        return text

    finding.evidence = clean(finding.evidence)
    finding.description = clean(finding.description)
    finding.explanation = clean(finding.explanation)
    finding.details = json.loads(clean(json.dumps(finding.details)))
    return finding


def run_security_engine(features: ProjectFeatures, project_root: Path,
                        package_results: list[dict] | None = None) -> tuple[list[Finding], list[ScanIssue], dict]:
    ctx = DetectionContext(features, build_purposes(project_root, package_results))
    findings: list[Finding] = []
    issues: list[ScanIssue] = []
    for name, detect in DETECTORS:
        try:
            findings.extend(detect(ctx))
        except Exception as error:  # noqa: BLE001 - one broken detector must not hide the others
            issues.append(ScanIssue("security", f"{name} detector failed: {type(error).__name__}: {error}",
                                    details={"traceback": traceback.format_exc(limit=3)}))
    try:
        secrets = credential_detector.secret_values(ctx)
    except Exception as error:  # noqa: BLE001
        secrets = set()
        issues.append(ScanIssue("security", f"secret collection failed: {error}"))
    findings = [scrub(f, secrets) for f in dedupe_findings(findings)]
    findings.sort(key=lambda f: (f.file or "", f.line or 0, f.rule_id))
    summary = {
        "files_with_features": len(features.files),
        "by_category": dict(Counter(f.category for f in findings)),
        "by_rule": dict(Counter(f.rule_id for f in findings)),
        "dependency_purposes": {k: {"source": v.source, "text": v.summary()} for k, v in ctx.purposes.items()},
        "unresolved_calls": sum(len(f.unresolved_calls) for f in features.files.values()),
        "indirect_calls": sum(len(f.indirect_calls) for f in features.files.values()),
    }
    if summary["indirect_calls"]:
        issues.append(ScanIssue("security", f"{summary['indirect_calls']} call(s) through function pointers or "
                                "callbacks could not be resolved to a target; their behaviour was not analysed.",
                                level="WARNING"))
    return findings, issues, summary
