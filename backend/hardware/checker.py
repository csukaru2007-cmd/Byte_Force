"""Component B - ESP32 hardware intelligence.

Input: gpio_operations extracted from the Clang AST (backend/ast_engine/ast_extractor.py)
Knowledge: the selected chip profile (databases/esp32_wroom_32.json)
Output: HW001-HW013 findings plus a pin-usage table.

Rules are deterministic comparisons between what the code requests and what the
datasheet says the pin can do. Non-constant pin numbers are reported as unresolved,
never guessed.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from backend.ast_engine.ast_extractor import ProjectFeatures
from backend.hardware.profiles import (ProfileError, board_info, load_profile, mcu_family_id,
                                       profile_for_mcu, resolve_profile)
from backend.models import Finding, ScanIssue
from backend.platformio.ini_parser import EnvironmentInfo
from backend.security_engine.rule_loader import hardware_rules

COMPONENT = "hardware_intelligence"
DRIVE_REQUIREMENTS = {"output"}
WIFI_CLASSES = {"WiFiClass", "WiFiSTAClass", "WiFiGenericClass", "WiFiAPClass"}
WIFI_FUNCTIONS = {"esp_wifi_start", "esp_wifi_connect", "esp_wifi_init"}


@dataclass
class HardwareResult:
    status: str                         # completed | skipped
    profile: dict | None = None
    selection: dict = field(default_factory=dict)
    boards: list[dict] = field(default_factory=list)
    operations_checked: int = 0
    unresolved_operations: int = 0
    pin_usage: list[dict] = field(default_factory=list)
    context: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"status": self.status, "profile": self.profile, "selection": self.selection,
                "boards": self.boards, "operations_checked": self.operations_checked,
                "unresolved_operations": self.unresolved_operations, "pin_usage": self.pin_usage,
                "context": self.context, "findings": [f.to_dict() for f in self.findings]}


def _project_context(features: ProjectFeatures) -> dict:
    wifi, serial0 = [], []
    for file_features, call in features.iter("function_calls"):
        if file_features.origin != "project" and not file_features.file.startswith("lib/"):
            continue
        types = {call["class_name"], call["object_type"], *call["object_bases"]} - {None}
        if types & WIFI_CLASSES or call["name"] in WIFI_FUNCTIONS:
            wifi.append(f"{file_features.file}:{call['line']} {call['display']}")
        if call["name"] == "begin" and call["object_name"] == "Serial" and "HardwareSerial" in types:
            serial0.append(f"{file_features.file}:{call['line']}")
    return {"wifi_used": bool(wifi), "wifi_evidence": wifi[:5],
            "serial0_used": bool(serial0), "serial0_evidence": serial0[:5]}


def _select_profile(chip: str | None, environments: list[EnvironmentInfo], result: HardwareResult) -> str | None:
    boards = []
    for env in environments:
        info = board_info(env.board)
        boards.append({"env": env.name, "board": env.board, "mcu": info["mcu"] if info else None,
                       "board_name": info["name"] if info else None,
                       "module_note": info.get("module_note") if info else None,
                       "known": info is not None})
    result.boards = boards
    if chip:
        try:
            profile_id = resolve_profile(chip)
        except ProfileError as error:
            result.issues.append(ScanIssue("hardware", str(error)))
            result.selection = {"requested": chip, "resolved_by": None, "error": str(error)}
            return None
        result.selection = {"requested": chip, "resolved_by": "user"}
        return profile_id

    known = [b for b in boards if b["mcu"]]
    if not known:
        message = ("No chip profile selected and the board in platformio.ini is not in the PlatformIO board list; "
                   "hardware checks were skipped. Select a chip profile to enable them.")
        result.issues.append(ScanIssue("hardware", message))
        result.selection = {"requested": None, "resolved_by": None, "error": message}
        return None
    mcus = {b["mcu"] for b in known}
    profile_id = profile_for_mcu(known[0]["mcu"])
    if profile_id is None:
        family = mcu_family_id(known[0]["mcu"]) or known[0]["mcu"]
        message = (f"Board '{known[0]['board']}' uses {known[0]['mcu']}; no verified hardware profile exists for "
                   f"{family} yet. Hardware checks were skipped.")
        result.issues.append(ScanIssue("hardware", message))
        result.selection = {"requested": None, "resolved_by": None, "error": message}
        return None
    if len(mcus) > 1:
        result.issues.append(ScanIssue("hardware", f"Environments target different MCUs ({sorted(mcus)}); "
                                       f"using {known[0]['mcu']} from [env:{known[0]['env']}].", level="WARNING"))
    result.selection = {"requested": None, "resolved_by": f"board '{known[0]['board']}' in [env:{known[0]['env']}]"}
    return profile_id


def check_hardware(features: ProjectFeatures, chip: str | None,
                   environments: list[EnvironmentInfo]) -> HardwareResult:
    result = HardwareResult(status="skipped")
    rules = hardware_rules()
    profile_id = _select_profile(chip, environments, result)
    if profile_id is None:
        return result
    profile = load_profile(profile_id)
    result.status = "completed"
    result.profile = {"id": profile_id, "module": profile["module"], "chip": profile["chip"],
                      "display_name": profile["display_name"],
                      "sources": [f"{s['title']} {s.get('version', '')}".strip() for s in profile["sources"]]}

    for board in result.boards:
        if board["mcu"] and board["mcu"] != profile["applies_to_mcu"]:
            result.findings.append(rules.finding(
                "HW011", file="platformio.ini", line=None, origin="platformio.ini",
                evidence=f"[env:{board['env']}] board = {board['board']} ({board['mcu']}); selected profile describes "
                         f"{profile['applies_to_mcu']} ({profile['module']})",
                details={"board": board, "profile": profile_id}))
            result.status = "completed_with_profile_mismatch"
        elif board.get("module_note"):
            result.issues.append(ScanIssue("hardware", f"[env:{board['env']}] {board['module_note']}", level="WARNING"))

    context = _project_context(features)
    result.context = context
    gpio = profile["gpio"]
    valid = set(profile["valid_gpio_numbers"])
    usage: dict[int, dict] = defaultdict(lambda: {"requirements": set(), "locations": []})
    reported_once: set[tuple] = set()

    def add(rule_id: str, op: dict, evidence: str, **kwargs) -> None:
        details = kwargs.pop("details", {})
        details.update({"gpio": op["gpio"], "operation": op["function"], "role": op["role"],
                        "requirement": op["requirement"], "mode": op["mode"], "profile": profile_id})
        result.findings.append(rules.finding(rule_id, file=op["file"], line=op["line"],
                                             evidence=evidence, origin=op["origin"], details=details, **kwargs))

    for file_features, op in features.iter("gpio_operations"):
        if op["origin"] != "project" and not op["file"].startswith("lib/"):
            continue                    # library code receives pins as parameters; checked at the call site
        result.operations_checked += 1
        call_text = f"{op['display']}({op['gpio_expr']}" + (f", {op['mode']})" if op["mode"] else ")")
        if not op["resolved"]:
            result.unresolved_operations += 1
            add("HW012", op, f"{call_text}: '{op['gpio_expr']}' is not a compile-time constant")
            continue
        number = op["gpio"]
        label = f"GPIO{number}" + (f" ({op['gpio_expr']})" if op["gpio_expr"] not in (str(number), "") else "")
        usage[number]["requirements"].add(op["requirement"])
        usage[number]["locations"].append(f"{op['file']}:{op['line']}")

        if number not in valid:
            add("HW004", op, f"{call_text}: GPIO{number} is not a GPIO of {profile['chip']}",
                description=f"GPIO{number} does not exist on the selected {profile['module']} profile.")
            continue
        pin = gpio[str(number)]
        requirement = op["requirement"]

        if requirement in DRIVE_REQUIREMENTS and pin["input_only"]:
            if op["mode"]:
                usage_text = op["mode"]
            elif op["role"] != "pin":
                usage_text = f"{op['role']} (an output signal)"
            else:
                usage_text = f"an output ({op['function']})"
            add("HW001", op, call_text, description=(
                f"{label} is input-only on the selected {profile['module']} profile and cannot be "
                f"configured as {usage_text}."))
        if pin["flash_connected"]:
            add("HW002", op, call_text, description=f"{label} is connected to the module's SPI flash "
                                                    f"({pin['module_pin']}) and should not be used as a GPIO.")
        if not pin["exposed_on_module"]:
            add("HW005", op, call_text, description=f"{label} exists on the chip but is not a pin of {profile['module']}.")
        if requirement == "adc" and not pin["adc"]:
            add("HW006", op, call_text, description=f"{label} has no ADC channel; {op['function']}() cannot read it.")
        if requirement == "dac" and not pin["dac"]:
            add("HW006", op, call_text, description=f"{label} has no DAC channel; dacWrite() only works on "
                                                    f"GPIO{profile['dac_channels']['DAC_1']}/GPIO{profile['dac_channels']['DAC_2']}.")
        if requirement == "touch" and not pin["touch"]:
            add("HW006", op, call_text, description=f"{label} is not a capacitive touch pin.")
        if requirement == "analog" and not pin["adc"] and not pin["dac"]:
            add("HW006", op, call_text, description=f"{label} has no analog (ADC/DAC) function.")
        if requirement == "input_pull" and not pin["internal_pull_resistors"]:
            add("HW007", op, call_text, description=f"{label} has no internal pull resistors; {op['mode'] or op['function']} has no effect.")
        if requirement == "adc" and pin["adc_unit"] == 2 and context["wifi_used"]:
            add("HW008", op, f"{call_text}; Wi-Fi used at {context['wifi_evidence'][0]}",
                description=f"{label} is {pin['adc']}; ADC2 cannot be used while Wi-Fi is used.",
                details={"wifi_evidence": context["wifi_evidence"]})
        if pin["strapping"] and requirement != "none":
            strap = profile["strapping_pins"][str(number)]
            driven = requirement in ("output", "input_pull", "any")
            severity = ("MEDIUM" if number == 12 else "LOW") if driven else "INFO"
            jtag = f" It is also JTAG signal {pin['jtag']}." if pin["jtag"] else ""
            add("HW003", op, call_text, severity=severity,
                description=f"{label} is a strapping pin ({strap['signal']}: {strap['controls']}).",
                explanation=(f"Default at reset: {strap['default_pull']} (value {strap['default_value']}). "
                             f"{strap['risk_when_driven']} {profile['strapping_note']}{jtag}"),
                details={"strapping": strap})
        if pin["jtag"] and not pin["strapping"] and ("HW010", number) not in reported_once:
            reported_once.add(("HW010", number))
            add("HW010", op, call_text, description=f"{label} is JTAG signal {pin['jtag']}; used here as GPIO.")
        if pin["uart0"]:
            severity = "LOW" if context["serial0_used"] else "INFO"
            add("HW009", op, call_text, severity=severity,
                description=f"{label} is UART0 {pin['uart0']} (U0{pin['uart0']}D)" +
                            (", and the project also uses Serial." if context["serial0_used"] else "."))
        if op["function"] == "attachInterrupt" and number in (36, 39):
            add("HW013", op, call_text)

    for number in sorted(usage):
        pin = gpio.get(str(number), {})
        result.pin_usage.append({
            "gpio": number, "requirements": sorted(usage[number]["requirements"]),
            "locations": usage[number]["locations"][:10],
            "capabilities": {k: pin.get(k) for k in ("input_only", "adc", "dac", "touch", "strapping",
                                                     "flash_connected", "jtag")} if pin else None})
    return result
