"""Category E - obfuscation indicators (OBF001-OBF004).

Encoded data alone is INFO: certificates, fonts and images are commonly embedded.
The severity comes from *combinations*: decoding next to a sensitive operation
(OBF003) and, stronger, encoded/decoded data flowing into that operation (OBF004).
"""

from __future__ import annotations

import re

from backend.models import Finding
from backend.security_engine.base import DetectionContext, call_label, first_match, functions, track

_BASE64 = re.compile(r"^[A-Za-z0-9+/\r\n]+={0,2}$")
_HEX = re.compile(r"^(0x)?[0-9a-fA-F\s]+$")


def encoding_of(value: str, min_length: int) -> str | None:
    compact = value.strip()
    if len(compact) < min_length:
        return None
    if _HEX.match(compact) and len(re.sub(r"\s", "", compact)) % 2 == 0:
        return "hexadecimal"
    if _BASE64.match(compact) and (len(compact.replace("\n", "").replace("\r", "")) % 4 == 0 or compact.endswith("=")):
        # require a mix of character classes so long plain identifiers are not counted
        if re.search(r"[A-Z]", compact) and re.search(r"[a-z]", compact) and re.search(r"[0-9+/]", compact):
            return "base64"
    return None


def detect(ctx: DetectionContext) -> list[Finding]:
    findings: list[Finding] = []
    rules = ctx.rules
    min_length = rules["OBF001"].detection["min_length"]
    min_elements = rules["OBF002"].detection["min_elements"]
    decode_apis = rules["OBF003"].detection["decode_apis"]
    sensitive = (rules["EXEC001"].detection["execution_functions"] + rules["FW004"].detection["write_sinks"])

    # seeds: variables holding large encoded literals or large arrays (usable from any function)
    seeds: dict[str, str] = {}
    for features in ctx.features.files.values():
        literal_lines = {}
        for literal in features.string_literals:
            encoding = encoding_of(literal["value"], min_length)
            if encoding:
                literal_lines[literal["line"]] = (encoding, literal["length"])
                findings.append(ctx.finding("OBF001", features, literal["line"],
                                            f"{encoding} literal, {literal['length']} characters",
                                            function=literal["enclosing_function"],
                                            details={"encoding": encoding, "length": literal["length"]}))
        for var in features.variable_declarations:
            if var["line"] in literal_lines:
                encoding, length = literal_lines[var["line"]]
                seeds[var["usr"] or var["name"]] = f"{encoding} literal {var['name']} ({length} chars, line {var['line']})"
        for array in features.array_initializers:
            if array["integer_count"] >= min_elements:
                findings.append(ctx.finding("OBF002", features, array["line"],
                                            f"{array['name']}: {array['element_count']} elements "
                                            f"({array['hex_literal_count']} hexadecimal literals)",
                                            function=array["enclosing_function"],
                                            details={"elements": array["element_count"]}))
                seeds[array["usr"] or array["name"]] = f"embedded array {array['name']} ({array['element_count']} elements)"

    for features in ctx.features.files.values():
        for function, parts in functions(features).items():
            taint, direct = track(parts, decode_apis, seeds)
            decode_calls = [c for c in parts["calls"] if first_match(c, decode_apis)]
            sinks = [(c, first_match(c, sensitive)) for c in parts["calls"]]
            sinks = [(c, api) for c, api in sinks if api]
            flowed = False
            for call, api in sinks:
                for index, arg in enumerate(call["arguments"]):
                    reason = taint.reason_for_arg(arg, direct)
                    if reason:
                        flowed = True
                        findings.append(ctx.finding(
                            "OBF004", features, call["line"], f"{call_label(call, 2)}: argument {index + 1} from {reason}",
                            function=function, details={"sink": api, "flow": reason}))
                        break
            for cast in parts["casts"]:
                reason = taint.reason_for_arg(cast, direct)
                if reason:
                    flowed = True
                    findings.append(ctx.finding(
                        "OBF004", features, cast["line"], f"({cast['to_type']}) {cast['operand']}: data from {reason}",
                        function=function, details={"sink": "function pointer cast", "flow": reason}))
            if decode_calls and (sinks or parts["casts"]) and not flowed:
                target = sinks[0][0] if sinks else None
                line = target["line"] if target else parts["casts"][0]["line"]
                findings.append(ctx.finding(
                    "OBF003", features, line,
                    f"{call_label(decode_calls[0], 2)} and {call_label(target, 2) if target else 'function pointer cast'}"
                    f" in {function}()", function=function))
    return findings
