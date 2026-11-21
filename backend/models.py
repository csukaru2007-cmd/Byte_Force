"""The unified finding format shared by all three components.

A Finding states *what was observed* and *why it matters*. It never states that a
project is malware. Risk scoring lives separately in backend/risk_engine.py.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

COMPONENTS = ("platformio_intelligence", "hardware_intelligence", "security_engine")
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# Confidence is qualitative. It is NOT a calibrated probability.
#   DEFINITE   - the stated fact was established deterministically
#                (e.g. the code calls pinMode(34, OUTPUT) and the datasheet says GPIO34 is input-only)
#   INDICATOR  - a pattern associated with risk is present; a human must judge intent
#   UNRESOLVED - the analysis could not decide (non-constant value, missing metadata, parse failure)
CONFIDENCES = ("DEFINITE", "INDICATOR", "UNRESOLVED")


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def raise_severity(severity: str, steps: int = 1) -> str:
    return SEVERITIES[min(len(SEVERITIES) - 1, severity_rank(severity) + steps)]


@dataclass
class Finding:
    component: str
    rule_id: str
    category: str
    severity: str
    description: str
    file: str | None = None
    line: int | None = None
    evidence: str = ""
    recommendation: str = ""
    confidence: str = "INDICATOR"
    explanation: str = ""
    # "project" for the user's own code, "dependency:<package>" for library code,
    # "platformio.ini" for configuration-level findings
    origin: str = "project"
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.component not in COMPONENTS:
            raise ValueError(f"unknown component {self.component!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"unknown confidence {self.confidence!r}")

    def dedup_key(self) -> tuple:
        return (self.component, self.rule_id, self.file, self.line, self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanIssue:
    """Something that limited the analysis: parser error, unavailable API, skipped file...

    Issues are reported next to findings so that an incomplete scan is never
    mistaken for a clean one.
    """

    stage: str                 # "upload", "dependencies", "registry", "parser", "hardware", "security"
    message: str
    level: str = "ERROR"       # "ERROR" or "WARNING"
    file: str | None = None
    line: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Drop findings that are identical in component, rule, location and evidence."""
    seen: set[tuple] = set()
    unique = []
    for finding in findings:
        key = finding.dedup_key()
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
