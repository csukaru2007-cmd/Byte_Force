"""Load and validate rule catalogs (databases/*_rules.json).

The JSON files *describe* each rule (ID, severity, explanation, recommendation,
limitations, and the API lists a detector looks for). The detection logic itself is
Python code in the detector modules; JSON is never the only implementation.

The same loader is used by all three components so that every finding carries the
same explanatory fields.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.config import DATABASES
from backend.models import COMPONENTS, CONFIDENCES, SEVERITIES, Finding

REQUIRED_FIELDS = (
    "rule_id", "category", "description", "severity", "applies_to",
    "detection_condition", "requires_context", "required_context",
    "explanation", "recommendation", "limitations",
)


class RuleCatalogError(ValueError):
    """A rule catalog file is missing, malformed or internally inconsistent."""


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    description: str
    severity: str
    applies_to: list[str]
    detection_condition: str
    requires_context: bool
    required_context: list[str]
    explanation: str
    recommendation: str
    limitations: list[str]
    default_confidence: str = "INDICATOR"
    detection: dict[str, Any] = field(default_factory=dict)

    def finding(self, component: str, *, file: str | None = None, line: int | None = None,
                evidence: str = "", severity: str | None = None, confidence: str | None = None,
                description: str | None = None, explanation: str | None = None,
                origin: str = "project", details: dict | None = None) -> Finding:
        """Build a Finding pre-filled with this rule's explanatory text."""
        return Finding(
            component=component,
            rule_id=self.rule_id,
            category=self.category,
            severity=severity or self.severity,
            description=description or self.description,
            file=file,
            line=line,
            evidence=evidence,
            recommendation=self.recommendation,
            confidence=confidence or self.default_confidence,
            explanation=explanation or self.explanation,
            origin=origin,
            details=dict(details or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id, "category": self.category, "description": self.description,
            "severity": self.severity, "applies_to": self.applies_to,
            "detection_condition": self.detection_condition,
            "requires_context": self.requires_context, "required_context": self.required_context,
            "explanation": self.explanation, "recommendation": self.recommendation,
            "limitations": self.limitations, "default_confidence": self.default_confidence,
        }


class RuleCatalog:
    def __init__(self, component: str, rules: dict[str, Rule], source: Path):
        self.component = component
        self.rules = rules
        self.source = source

    def __getitem__(self, rule_id: str) -> Rule:
        try:
            return self.rules[rule_id]
        except KeyError:
            raise RuleCatalogError(f"rule {rule_id} is not defined in {self.source.name}") from None

    def __iter__(self):
        return iter(self.rules.values())

    def finding(self, rule_id: str, **kwargs) -> Finding:
        return self[rule_id].finding(self.component, **kwargs)


def parse_catalog(data: dict, source: Path) -> RuleCatalog:
    component = data.get("component")
    if component not in COMPONENTS:
        raise RuleCatalogError(f"{source.name}: 'component' must be one of {COMPONENTS}")
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleCatalogError(f"{source.name}: 'rules' must be a non-empty list")
    rules: dict[str, Rule] = {}
    for index, raw in enumerate(raw_rules):
        missing = [name for name in REQUIRED_FIELDS if name not in raw]
        if missing:
            raise RuleCatalogError(f"{source.name}: rule #{index} is missing {missing}")
        if raw["severity"] not in SEVERITIES:
            raise RuleCatalogError(f"{source.name}: {raw['rule_id']} has invalid severity {raw['severity']!r}")
        confidence = raw.get("default_confidence", "INDICATOR")
        if confidence not in CONFIDENCES:
            raise RuleCatalogError(f"{source.name}: {raw['rule_id']} has invalid confidence {confidence!r}")
        if raw["rule_id"] in rules:
            raise RuleCatalogError(f"{source.name}: duplicate rule_id {raw['rule_id']}")
        for list_field in ("applies_to", "required_context", "limitations"):
            if not isinstance(raw[list_field], list):
                raise RuleCatalogError(f"{source.name}: {raw['rule_id']}.{list_field} must be a list")
        rules[raw["rule_id"]] = Rule(
            rule_id=raw["rule_id"], category=raw["category"], description=raw["description"],
            severity=raw["severity"], applies_to=raw["applies_to"],
            detection_condition=raw["detection_condition"],
            requires_context=bool(raw["requires_context"]), required_context=raw["required_context"],
            explanation=raw["explanation"], recommendation=raw["recommendation"],
            limitations=raw["limitations"], default_confidence=confidence,
            detection=raw.get("detection", {}),
        )
    return RuleCatalog(component, rules, source)


@lru_cache(maxsize=None)
def load_catalog(filename: str) -> RuleCatalog:
    path = DATABASES / filename
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise RuleCatalogError(f"cannot read rule catalog {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise RuleCatalogError(f"{path.name} is not valid JSON: {error}") from error
    return parse_catalog(data, path)


def security_rules() -> RuleCatalog:
    return load_catalog("security_rules.json")


def hardware_rules() -> RuleCatalog:
    return load_catalog("hardware_rules.json")


def package_rules() -> RuleCatalog:
    return load_catalog("package_rules.json")
