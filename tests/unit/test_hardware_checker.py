"""The nine required hardware scenarios, plus the remaining hardware rules.

Every test checks both what must be reported and what must NOT be reported.
"""

from backend.hardware.checker import check_hardware
from tests.helpers import analyse_fixture, line_of


def _check(name, tmp_path, chip="ESP32-WROOM-32"):
    root, extraction, analysis = analyse_fixture(name, tmp_path)
    result = check_hardware(analysis.features, chip, extraction.environments)
    return root, result


def _ids(result):
    return [f.rule_id for f in result.findings]


# 1. GPIO34 configured as OUTPUT
def test_gpio34_output_is_reported(tmp_path):
    root, result = _check("hardware/gpio34_output", tmp_path)
    hw001 = [f for f in result.findings if f.rule_id == "HW001"]
    assert len(hw001) == 2           # pinMode(34, OUTPUT) and digitalWrite(34, HIGH)
    first = hw001[0]
    assert first.severity == "HIGH" and first.confidence == "DEFINITE"
    assert first.description == ("GPIO34 is input-only on the selected ESP32-WROOM-32 profile and cannot be "
                                 "configured as OUTPUT.")
    assert first.file == "src/main.cpp" and first.line == line_of(root, "src/main.cpp", "pinMode(34, OUTPUT)")
    assert first.evidence == "pinMode(34, OUTPUT)"
    assert first.component == "hardware_intelligence"


# 2. GPIO34 configured as INPUT
def test_gpio34_input_is_accepted(tmp_path):
    _, result = _check("hardware/gpio34_input", tmp_path)
    assert result.status == "completed" and result.operations_checked == 3
    assert result.findings == []


# 3. GPIO23 configured as OUTPUT
def test_gpio23_output_is_accepted(tmp_path):
    _, result = _check("hardware/gpio23_output", tmp_path)
    assert result.operations_checked == 3 and result.findings == []
    assert result.pin_usage[0]["gpio"] == 23


def _pin_rules(tmp_path):
    root, result = _check("hardware/pin_rules", tmp_path)
    by_line = {}
    for f in result.findings:
        by_line.setdefault(f.line, []).append(f)
    return root, result, by_line


# 4. flash-connected pin
def test_flash_pin(tmp_path):
    root, _, by_line = _pin_rules(tmp_path)
    [finding] = by_line[line_of(root, "src/main.cpp", "FLASH_CLK_PIN, OUTPUT")]
    assert finding.rule_id == "HW002" and finding.severity == "HIGH" and "SCK/CLK" in finding.description


# 5. strapping pin
def test_strapping_pin_is_contextual(tmp_path):
    root, result, by_line = _pin_rules(tmp_path)
    [gpio12] = by_line[line_of(root, "src/main.cpp", "STATUS_LED, OUTPUT")]
    assert gpio12.rule_id == "HW003" and gpio12.severity == "MEDIUM"
    assert "MTDI" in gpio12.description and "1.8 V" in gpio12.explanation and "JTAG" in gpio12.explanation
    assert gpio12.confidence == "INDICATOR"


def test_strapping_pin_read_only_is_info(tmp_path):
    root, result = _check("benign/normal_sensor_project", tmp_path)
    assert result.findings == []          # 21/22/23/34 are not strapping pins
    from tests.helpers import write_project
    from backend.ast_engine.runner import analyse_sources
    from backend.platformio.ini_parser import extract_dependencies
    project = write_project(tmp_path / "s", {
        "platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n",
        "src/main.cpp": "#include <Arduino.h>\nvoid setup(){ pinMode(0, INPUT); }\nvoid loop(){}\n"})
    extraction = extract_dependencies(project)
    strap = check_hardware(analyse_sources(project, extraction.environments[0], tmp_path / "w").features,
                           None, extraction.environments)
    assert [(f.rule_id, f.severity) for f in strap.findings] == [("HW003", "INFO")]


# 6. unknown GPIO
def test_unknown_gpio(tmp_path):
    root, _, by_line = _pin_rules(tmp_path)
    [gpio20] = by_line[line_of(root, "src/main.cpp", "pinMode(20, OUTPUT)")]
    assert gpio20.rule_id == "HW004" and gpio20.severity == "HIGH"
    [gpio37] = by_line[line_of(root, "src/main.cpp", "pinMode(37, INPUT)")]
    assert gpio37.rule_id == "HW005"


# 7. non-constant GPIO argument
def test_non_constant_gpio_is_unresolved(tmp_path):
    root, result, by_line = _pin_rules(tmp_path)
    [finding] = by_line[line_of(root, "src/main.cpp", "pinMode(pinFromConfig()")]
    assert finding.rule_id == "HW012" and finding.confidence == "UNRESOLVED" and finding.severity == "INFO"
    assert result.unresolved_operations == 1


# 8. missing chip selection
def test_missing_chip_selection_uses_board_or_skips(tmp_path):
    _, auto = _check("hardware/gpio34_output", tmp_path / "a", chip=None)
    assert auto.selection["resolved_by"].startswith("board 'esp32dev'") and "HW001" in _ids(auto)
    _, skipped = _check("hardware/unknown_board", tmp_path / "b", chip=None)
    assert skipped.status == "skipped" and skipped.findings == []
    assert "hardware checks were skipped" in skipped.issues[0].message


# 9. wrong chip profile
def test_wrong_chip_profile(tmp_path):
    _, mismatch = _check("hardware/esp32s3_board", tmp_path / "a", chip="ESP32-WROOM-32")
    assert mismatch.status == "completed_with_profile_mismatch"
    hw011 = [f for f in mismatch.findings if f.rule_id == "HW011"]
    assert hw011 and "ESP32S3" in hw011[0].evidence
    _, unsupported = _check("hardware/esp32s3_board", tmp_path / "b", chip="ESP32-S3")
    assert unsupported.status == "skipped" and unsupported.findings == []
    assert "No verified hardware profile for ESP32-S3" in unsupported.issues[0].message
    _, auto = _check("hardware/esp32s3_board", tmp_path / "c", chip=None)
    assert auto.status == "skipped" and "no verified hardware profile" in auto.issues[0].message


def test_remaining_rules(tmp_path):
    root, result, by_line = _pin_rules(tmp_path)

    def rules_at(needle):
        return sorted(f.rule_id for f in by_line.get(line_of(root, "src/main.cpp", needle), []))

    assert rules_at("pinMode(35, INPUT_PULLUP)") == ["HW007"]
    assert rules_at("dacWrite(4, 128)") == ["HW006"]
    assert rules_at("touchRead(26)") == ["HW006"]
    assert rules_at("GPIO_NUM_39, GPIO_MODE_OUTPUT") == ["HW001"]
    assert rules_at("pinMode(1, OUTPUT)") == ["HW009"]
    assert rules_at("pinMode(14, OUTPUT)") == ["HW010"]
    assert rules_at("attachInterrupt(36") == ["HW013"]
    assert rules_at("analogRead(25)") == ["HW008"]
    # correct uses produce nothing
    for ok in ("analogRead(32)", "dacWrite(25, 10)", "touchRead(4)"):
        assert rules_at(ok) == [], ok
    assert result.context["wifi_used"] and result.context["serial0_used"]
