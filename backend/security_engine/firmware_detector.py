"""Category D - firmware and sensitive operations (FW001-FW007).

OTA support itself is INFO: it is a normal maintenance feature. Findings rise when the
update path lacks authentication or transport security, or when permanent/raw
operations appear (eFuse burning, direct flash writes, boot partition switches).
"""

from __future__ import annotations

from backend.models import Finding
from backend.security_engine.base import DetectionContext, call_label, call_types, first_match, functions


def detect(ctx: DetectionContext) -> list[Finding]:
    findings: list[Finding] = []
    rules = ctx.rules
    update_apis = rules["FW001"].detection["update_apis"]
    flash_apis = rules["FW004"].detection["flash_apis"]
    efuse_apis = rules["FW005"].detection["efuse_apis"]
    debug_apis = rules["FW007"].detection["debug_apis"]

    ota_begin, ota_password = [], False
    for features in ctx.features.files.values():
        for call in features.function_calls:
            if "ArduinoOTAClass" in call_types(call):
                if call["name"] == "begin":
                    ota_begin.append((features, call))
                elif call["name"] in ("setPassword", "setPasswordHash"):
                    ota_password = True

    for features in ctx.features.files.values():
        for function, parts in functions(features).items():
            calls = parts["calls"]
            update_calls = [(c, first_match(c, update_apis)) for c in calls]
            update_calls = [(c, api) for c, api in update_calls if api]
            if update_calls:
                first = update_calls[0][0]
                severity, context_text, _ = ctx.contextual("INFO", features.origin, "firmware")
                findings.append(ctx.finding(
                    "FW001", features, first["line"], "; ".join(dict.fromkeys(call_label(c, 2) for c, _ in update_calls)),
                    severity=severity, function=function,
                    explanation=f"{rules['FW001'].explanation} {context_text}",
                    details={"apis": sorted({api for _, api in update_calls})}))

            insecure_objects = {c["object_name"] for c in calls if c["name"] == "setInsecure"}
            for call in calls:
                if not first_match(call, ["HTTPUpdate::update", "HTTPUpdate::updateSpiffs"]):
                    continue
                url = next((a["value"] for a in call["arguments"] if isinstance(a["value"], str)
                            and a["value"].lower().startswith(("http://", "https://"))), None)
                client = call["arguments"][0]["text"] if call["arguments"] else ""
                reasons = []
                if url and url.lower().startswith("http://"):
                    reasons.append(f"plain HTTP URL {url}")
                if client in insecure_objects:
                    reasons.append(f"client '{client}' has certificate verification disabled (setInsecure)")
                if reasons:
                    findings.append(ctx.finding("FW003", features, call["line"],
                                                f"{call_label(call, 2)}: {'; '.join(reasons)}", function=function))

            for call in calls:
                api = first_match(call, flash_apis)
                if api:
                    severity, context_text, _ = ctx.contextual("LOW", features.origin, "storage")
                    findings.append(ctx.finding("FW004", features, call["line"], call_label(call), severity=severity,
                                                function=function, details={"api": api},
                                                explanation=f"{rules['FW004'].explanation} {context_text}"))
                api = first_match(call, efuse_apis)
                if api:
                    findings.append(ctx.finding("FW005", features, call["line"], call_label(call),
                                                function=function, details={"api": api}))
                api = first_match(call, debug_apis)
                if api:
                    findings.append(ctx.finding("FW007", features, call["line"], call_label(call),
                                                function=function, details={"api": api}))
                if call["name"] == "esp_ota_set_boot_partition" and call["class_name"] is None:
                    completes = any(c["name"] == "esp_ota_end" or
                                    (c["name"] == "end" and "UpdateClass" in call_types(c)) for c in calls)
                    if not completes:
                        findings.append(ctx.finding("FW006", features, call["line"], call_label(call),
                                                    function=function))

    if ota_begin and not ota_password:
        for features, call in ota_begin:
            findings.append(ctx.finding("FW002", features, call["line"],
                                        f"{call['display']}() with no setPassword()/setPasswordHash() in the project",
                                        function=call["enclosing_function"]))
    return findings
