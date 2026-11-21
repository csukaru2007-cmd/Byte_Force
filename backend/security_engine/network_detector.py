"""Category A - network behaviour (NET001-NET005).

Ordinary networking is reported at INFO level. Severity only rises when context makes
the communication unexpected: a dependency whose stated purpose does not involve
networking (NET002), or a hard-coded destination inside library code (NET003).
"""

from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict

from backend.models import Finding
from backend.security_engine.base import DetectionContext, call_label, call_types, redact_url

_URL = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.-]*)://(?P<host>[^/:?#]+)", re.IGNORECASE)
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
CLEARTEXT = {"http", "ws", "mqtt", "ftp", "telnet"}


def endpoint_of(value) -> dict | None:
    """Classify a constant argument as URL, IP address or host name."""
    if not isinstance(value, str) or not value or len(value) > 2048:
        return None
    match = _URL.match(value)
    if match:
        return {"kind": "url", "scheme": match.group("scheme").lower(), "host": match.group("host"), "value": value}
    try:
        address = ipaddress.ip_address(value)
        note = ("documentation range" if any(address in ipaddress.ip_network(n) for n in
                                             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
                else "private network" if address.is_private else "public address")
        return {"kind": "ip", "scheme": None, "host": value, "value": value, "note": note}
    except ValueError:
        pass
    if _HOST.match(value):
        return {"kind": "host", "scheme": None, "host": value, "value": value}
    return None


def is_network_call(call: dict, spec: dict) -> bool:
    if call["callee_kind"] == "constructor":
        return False
    types = call_types(call)
    if types & set(spec["network_classes"]):
        return call["name"] in spec["network_methods"]
    return call["class_name"] is None and call["name"] in spec["network_functions"]


def detect(ctx: DetectionContext) -> list[Finding]:
    findings: list[Finding] = []
    spec = ctx.rules["NET001"].detection
    endpoint_methods = set(ctx.rules["NET003"].detection["endpoint_methods"])

    for features in ctx.features.files.values():
        per_function: OrderedDict[str, list[dict]] = OrderedDict()
        for call in features.function_calls:
            if not is_network_call(call, spec):
                if call["name"] == "setInsecure" and call_types(call) & {"WiFiClientSecure", "NetworkClientSecure"}:
                    findings.append(ctx.finding("NET005", features, call["line"], call_label(call),
                                                function=call["enclosing_function"]))
                continue
            per_function.setdefault(call["enclosing_function"], []).append(call)

            if call["name"] in endpoint_methods:
                for arg in call["arguments"]:
                    endpoint = endpoint_of(arg["value"])
                    if endpoint is None:
                        continue
                    shown = redact_url(endpoint["value"])
                    # Application code choosing its own server is normal: inventory only (INFO).
                    # A library that decides where data goes deserves review (MEDIUM).
                    severity = "INFO" if features.origin == "project" else "MEDIUM"
                    note = f" ({endpoint['note']})" if endpoint.get("note") else ""
                    findings.append(ctx.finding(
                        "NET003", features, call["line"], f"{call['display']}(\"{shown}\"){note}",
                        severity=severity, function=call["enclosing_function"],
                        details={"endpoint": {**endpoint, "value": shown}}))
                    if endpoint["scheme"] in CLEARTEXT:
                        findings.append(ctx.finding(
                            "NET004", features, call["line"], f"{call['display']}(\"{shown}\")",
                            function=call["enclosing_function"], details={"scheme": endpoint["scheme"]}))

        for function, calls in per_function.items():
            first = calls[0]
            operations = list(OrderedDict.fromkeys(call_label(c, 2) for c in calls))
            evidence = "; ".join(operations[:6]) + (f"; +{len(operations) - 6} more" if len(operations) > 6 else "")
            base = "INFO" if features.origin == "project" else "LOW"
            severity, context_text, mismatch = ctx.contextual("INFO", features.origin, "network")
            details = {"operations": operations, "lines": sorted({c["line"] for c in calls}),
                       "context": context_text}
            if mismatch:
                findings.append(ctx.finding("NET002", features, first["line"], evidence, function=function,
                                            explanation=f"{ctx.rules['NET002'].explanation} {context_text}",
                                            details=details))
            else:
                if mismatch is None:
                    severity = base          # dependency with unknown purpose
                findings.append(ctx.finding("NET001", features, first["line"], evidence, severity=severity,
                                            function=function,
                                            explanation=f"{ctx.rules['NET001'].explanation} {context_text}",
                                            details=details))
    return findings
