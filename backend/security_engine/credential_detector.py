"""Category B - credential exposure (CRED001-CRED004).

Secret values are never written to the report: evidence shows only the first two
characters and the length. A variable merely *named* password is not reported; it
needs a non-placeholder literal value, and empty/placeholder values are ignored.
"""

from __future__ import annotations

import re

from backend.models import Finding
from backend.security_engine.base import DetectionContext, call_types, first_match, redact, redact_url

_QUERY = re.compile(r"(?i)[?&]([a-z_]*?(?:token|key|apikey|api_key|password|pass|secret|auth)[a-z_]*)=([^&#\s]+)")


class _Names:
    def __init__(self, detection: dict):
        self.secret = re.compile(detection["credential_name_pattern"])
        self.not_secret = re.compile(detection["non_secret_name_pattern"])
        self.placeholder = re.compile(detection["placeholder_pattern"])

    def credential_name(self, name: str | None) -> bool:
        return bool(name) and bool(self.secret.search(name)) and not self.not_secret.search(name)

    def real_value(self, value) -> bool:
        if not isinstance(value, str):
            return False
        stripped = value.strip()
        if len(stripped) < 4 or len(set(stripped)) == 1:
            return False
        return not self.placeholder.match(stripped)


def secret_values(ctx: DetectionContext) -> set[str]:
    """Every literal value this detector would treat as a secret. The engine masks these
    values in *all* findings, so no other detector's evidence can leak them."""
    names = _Names(ctx.rules["CRED001"].detection)
    patterns = [re.compile(p) for p in ctx.rules["CRED002"].detection["secret_patterns"].values()]
    credential_apis = ctx.rules["CRED001"].detection["credential_apis"]
    values: set[str] = set()
    for features in ctx.features.files.values():
        for literal in features.string_literals:
            if any(p.search(literal["value"]) for p in patterns):
                values.add(literal["value"])
            for _, secret in _QUERY.findall(literal["value"]):
                if names.real_value(secret):
                    values.add(secret)
        for var in features.variable_declarations:
            init = var.get("init") or {}
            if init.get("kind") == "string_literal" and names.credential_name(var["name"]) \
                    and names.real_value(init.get("value")):
                values.add(init["value"])
        for macro in features.macro_definitions:
            if names.credential_name(macro["name"]) and names.real_value(macro["string_value"]):
                values.add(macro["string_value"])
        for call in features.function_calls:
            api = first_match(call, credential_apis)
            for index in credential_apis.get(api, []) if api else []:
                if index < len(call["arguments"]):
                    arg = call["arguments"][index]
                    if arg["kind"] == "string_literal" and names.real_value(arg["value"]):
                        values.add(arg["value"])
    return values


def _is_log(call: dict, log_spec: dict) -> bool:
    """Serial/UART printing and log functions. client.print() is network output, not logging."""
    if call["class_name"] is None:
        return call["name"] in log_spec["log_functions"]
    if not first_match(call, log_spec["log_methods"]):
        return False
    return "HardwareSerial" in call_types(call) or (call["object_name"] or "").startswith("Serial")


def detect(ctx: DetectionContext) -> list[Finding]:
    findings: list[Finding] = []
    names = _Names(ctx.rules["CRED001"].detection)
    patterns = {label: re.compile(p) for label, p in ctx.rules["CRED002"].detection["secret_patterns"].items()}
    credential_apis = ctx.rules["CRED001"].detection["credential_apis"]
    log_spec = ctx.rules["CRED003"].detection
    reported_values: dict[str, Finding] = {}          # secret value -> finding (to link later uses)
    pattern_lines: set[tuple[str, int]] = set()

    # CRED002 / CRED004: literal formats, independent of names
    for features in ctx.features.files.values():
        for literal in features.string_literals:
            value = literal["value"]
            for label, pattern in patterns.items():
                if pattern.search(value):
                    finding = ctx.finding("CRED002", features, literal["line"], f"{label}: \"{redact(value)}\"",
                                          function=literal["enclosing_function"], details={"format": label})
                    findings.append(finding)
                    reported_values[value] = finding
                    pattern_lines.add((features.file, literal["line"]))
                    break
            for key, secret in _QUERY.findall(value):
                if names.real_value(secret):
                    findings.append(ctx.finding("CRED004", features, literal["line"],
                                                f"\"{redact_url(value)}\" (parameter '{key}')",
                                                function=literal["enclosing_function"]))

    # CRED001: credential-named variables and macros with real literal values
    for features in ctx.features.files.values():
        for var in features.variable_declarations:
            init = var.get("init") or {}
            value = init.get("value")
            if init.get("kind") == "string_literal" and names.credential_name(var["name"]) and names.real_value(value):
                if (features.file, var["line"]) in pattern_lines:
                    continue
                finding = ctx.finding("CRED001", features, var["line"], f"{var['name']} = \"{redact(value)}\"",
                                      function=var["enclosing_function"],
                                      details={"identifier": var["name"], "kind": "variable", "uses": []})
                findings.append(finding)
                reported_values.setdefault(value, finding)
        for macro in features.macro_definitions:
            value = macro["string_value"]
            if names.credential_name(macro["name"]) and names.real_value(value):
                if (features.file, macro["line"]) in pattern_lines:
                    continue
                finding = ctx.finding("CRED001", features, macro["line"],
                                      f"#define {macro['name']} \"{redact(value)}\"",
                                      details={"identifier": macro["name"], "kind": "macro", "uses": []})
                findings.append(finding)
                reported_values.setdefault(value, finding)

    # CRED001 (API position) and CRED003 (logging)
    secret_vars = {}
    for features in ctx.features.files.values():
        for var in features.variable_declarations:
            init = var.get("init") or {}
            if init.get("kind") == "string_literal" and names.real_value(init.get("value")):
                secret_vars[var["usr"] or var["name"]] = (var["name"], init["value"])

    for features in ctx.features.files.values():
        for call in features.function_calls:
            api = first_match(call, credential_apis)
            if api:
                for index in credential_apis[api]:
                    if index >= len(call["arguments"]):
                        continue
                    arg = call["arguments"][index]
                    value = arg["value"] if arg["kind"] == "string_literal" else None
                    source = "literal"
                    if value is None:
                        for ref in arg["references"]:
                            hit = secret_vars.get(ref.get("usr") or ref["name"])
                            if hit:
                                value, source = hit[1], f"variable {hit[0]}"
                    if not names.real_value(value):
                        continue
                    use = f"{features.file}:{call['line']} {call['display']}() argument {index + 1}"
                    if value in reported_values:
                        reported_values[value].details.setdefault("uses", []).append(use)
                        continue
                    shown = arg["text"] if arg["macro"] or source != "literal" else f"\"{redact(value)}\""
                    finding = ctx.finding(
                        "CRED001", features, call["line"],
                        f"{call['display']}(... {shown} ...) -> \"{redact(value)}\"",
                        function=call["enclosing_function"],
                        description=f"Potential hardcoded credential passed to {api}().",
                        details={"api": api, "argument": index + 1, "source": source, "uses": [use]})
                    findings.append(finding)
                    reported_values[value] = finding

            if not _is_log(call, log_spec):
                continue
            for arg in call["arguments"]:
                culprit = None
                if arg["macro"] and names.credential_name(arg["macro"]):
                    culprit = arg["macro"]
                for ref in arg["references"]:
                    if names.credential_name(ref["name"]):
                        culprit = ref["name"]
                if culprit is None and arg["kind"] == "string_literal" and arg["value"] in reported_values:
                    culprit = "a hardcoded credential value"
                if culprit:
                    findings.append(ctx.finding("CRED003", features, call["line"],
                                                f"{call['display']}({arg['text'] or culprit})",
                                                function=call["enclosing_function"],
                                                details={"identifier": culprit}))
                    break
    return findings
