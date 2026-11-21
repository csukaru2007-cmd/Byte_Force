"""Category C - dynamic execution (EXEC001-EXEC003)."""

from __future__ import annotations

from backend.models import Finding
from backend.security_engine.base import DetectionContext, call_label, first_match, functions, track


def detect(ctx: DetectionContext) -> list[Finding]:
    findings: list[Finding] = []
    exec_apis = ctx.rules["EXEC001"].detection["execution_functions"]
    sources = ctx.rules["EXEC002"].detection["network_sources"]

    for features in ctx.features.files.values():
        for function, parts in functions(features).items():
            taint, direct = track(parts, sources)
            for call in parts["calls"]:
                api = first_match(call, exec_apis)
                if api is None:
                    continue
                severity, context_text, _ = ctx.contextual("MEDIUM", features.origin, "execution")
                findings.append(ctx.finding(
                    "EXEC001", features, call["line"], call_label(call), severity=severity, function=function,
                    explanation=f"{ctx.rules['EXEC001'].explanation} {context_text}", details={"api": api}))
                for index, arg in enumerate(call["arguments"]):
                    reason = taint.reason_for_arg(arg, direct)
                    if reason:
                        findings.append(ctx.finding(
                            "EXEC002", features, call["line"], f"{call_label(call)}: argument {index + 1} from {reason}",
                            function=function, details={"sink": api, "flow": reason}))
                        break
            for cast in parts["casts"]:
                findings.append(ctx.finding(
                    "EXEC003", features, cast["line"], f"({cast['to_type']}) {cast['operand']}  [{cast['from_type']}]",
                    function=function, details={"from_type": cast["from_type"], "to_type": cast["to_type"]}))
                reason = taint.reason_for_arg(cast, direct)
                if reason:
                    findings.append(ctx.finding(
                        "EXEC002", features, cast["line"],
                        f"({cast['to_type']}) {cast['operand']}: data from {reason}",
                        function=function, details={"sink": "function pointer cast", "flow": reason}))
    return findings
