"""Clang parsing and AST feature extraction."""

import json

from backend.ast_engine.ast_extractor import decode_c_string
from backend.ast_engine.compile_context import build_context
from backend.ast_engine.runner import analyse_sources
from backend.platformio.ini_parser import extract_dependencies
from tests.helpers import analyse_fixture, line_of, write_project


def _ops(analysis, rel="src/main.cpp"):
    return analysis.features.files[rel].gpio_operations


def test_parses_project_with_clang(tmp_path):
    root, _, analysis = analyse_fixture("hardware/gpio23_output", tmp_path)
    [result] = analysis.parse_results
    assert result.file == "src/main.cpp" and result.status == "parsed" and result.error_count == 0
    features = analysis.features.files["src/main.cpp"]
    names = {d["qualified_name"] for d in features.function_declarations}
    assert {"setup", "loop"} <= names
    call = next(c for c in features.function_calls if c["name"] == "pinMode")
    assert call["qualified_name"] == "pinMode" and call["resolved"]
    assert [a["text"] for a in call["arguments"]] == ["RELAY_PIN", "OUTPUT"]
    assert [a["value"] for a in call["arguments"]] == [23, 3]
    assert call["line"] == line_of(root, "src/main.cpp", "pinMode(RELAY_PIN")
    assert call["enclosing_function"] == "setup"


def test_gpio_extraction_constant_macro_and_build_flag(tmp_path):
    root, _, analysis = analyse_fixture("hardware/pin_rules", tmp_path)
    ops = {(o["gpio_expr"], o["function"]): o for o in _ops(analysis)}
    flash = ops[("FLASH_CLK_PIN", "pinMode")]
    assert (flash["gpio"], flash["mode"], flash["requirement"]) == (6, "OUTPUT", "output")
    assert ops[("STATUS_LED", "pinMode")]["gpio"] == 12                     # -D STATUS_LED=12
    assert ops[("GPIO_NUM_39", "gpio_set_direction")]["mode"] == "GPIO_MODE_OUTPUT"
    assert ops[("35", "pinMode")]["requirement"] == "input_pull"
    unresolved = ops[("pinFromConfig ( )", "pinMode")]
    assert unresolved["resolved"] is False and unresolved["gpio"] is None
    assert unresolved["line"] == line_of(root, "src/main.cpp", "pinMode(pinFromConfig()")


def test_peripheral_pin_arguments(tmp_path):
    root = write_project(tmp_path / "p", {
        "platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n",
        "src/main.cpp": "#include <Arduino.h>\n#include <Wire.h>\n#include <SPI.h>\n"
                        "void setup(){\n Wire.begin(34, 22);\n SPI.begin(18, 19, 23, 5);\n"
                        " Serial2.begin(9600, SERIAL_8N1, 16, 17);\n ledcAttachPin(36, 0);\n}\nvoid loop(){}\n"})
    analysis = analyse_sources(root, extract_dependencies(root).environments[0], tmp_path / "w")
    ops = [(o["role"], o["gpio"], o["requirement"]) for o in _ops(analysis)]
    assert ("SDA", 34, "output") in ops and ("SCL", 22, "output") in ops
    assert ("MISO", 19, "input") in ops and ("MOSI", 23, "output") in ops
    assert ("TX", 17, "output") in ops and ("RX", 16, "input") in ops
    assert ("pin", 36, "output") in ops


def test_network_calls_objects_and_strings(tmp_path):
    root, _, analysis = analyse_fixture("suspicious_indicators/unexpected_network_call", tmp_path)
    lib = analysis.features.files["lib/TempProbe/src/TempProbe.cpp"]
    assert lib.origin == "dependency:TempProbe"
    connect = next(c for c in lib.function_calls if c["name"] == "connect")
    assert connect["display"] == "client.connect"
    assert connect["object_type"] == "WiFiClient" and connect["class_name"] == "NetworkClient"
    assert "Client" in connect["object_bases"]
    assert connect["arguments"][0]["value"] == "203.0.113.50"
    assert connect["enclosing_function"] == "TempProbe::report"
    assert connect["line"] == line_of(root, "lib/TempProbe/src/TempProbe.cpp", "client.connect(")
    assert any(o["name"] == "client" and o["type"] == "WiFiClient" for o in lib.object_declarations)
    assert any(s["value"] == "203.0.113.50" for s in lib.string_literals)


def test_macros_variables_and_assignments(tmp_path):
    _, _, analysis = analyse_fixture("suspicious_indicators/hardcoded_test_credential", tmp_path)
    f = analysis.features.files["src/main.cpp"]
    macro = next(m for m in f.macro_definitions if m["name"] == "WIFI_PASSWORD")
    assert macro["string_value"] == "FakePass-For-Tests-123"
    token = next(v for v in f.variable_declarations if v["name"] == "api_token")
    assert token["init"]["value"].startswith("sk_test_FAKE") and token["scope"] == "global"
    begin = next(c for c in f.function_calls if c["display"] == "WiFi.begin")
    assert begin["arguments"][1]["text"] == "WIFI_PASSWORD" and begin["arguments"][1]["macro"] == "WIFI_PASSWORD"


def test_missing_header_is_stubbed_and_reported(tmp_path):
    root = write_project(tmp_path / "p", {
        "platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n",
        "src/main.cpp": "#include <Arduino.h>\n#include <SomeVendorLib.h>\nVendorThing thing;\n"
                        "void setup(){ pinMode(34, OUTPUT); }\nvoid loop(){}\n"})
    analysis = analyse_sources(root, extract_dependencies(root).environments[0], tmp_path / "w")
    [result] = analysis.parse_results
    assert result.stubbed_headers == ["SomeVendorLib.h"]
    assert result.status == "parsed_with_errors"
    assert any("VendorThing" in d.message for d in result.diagnostics)
    # the rest of the file is still analysed
    assert _ops(analysis)[0]["gpio"] == 34
    assert any(i.stage == "parser" and i.file == "src/main.cpp" for i in analysis.issues)


def test_syntax_error_is_recorded_not_discarded(tmp_path):
    root = write_project(tmp_path / "p", {
        "platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n",
        "src/main.cpp": "#include <Arduino.h>\nvoid setup() { pinMode(23, OUTPUT) }\nvoid loop(){}\n"})
    analysis = analyse_sources(root, extract_dependencies(root).environments[0], tmp_path / "w")
    [result] = analysis.parse_results
    assert result.status == "parsed_with_errors" and result.diagnostics[0].line == 2
    assert analysis.issues[0].level == "WARNING"


def test_ino_files_and_multiple_files(tmp_path):
    root = write_project(tmp_path / "p", {
        "platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n",
        "src/app.ino": "void setup(){ pinMode(2, OUTPUT); }\nvoid loop(){}\n",
        "src/helper.cpp": "#include <Arduino.h>\nvoid blink(){ digitalWrite(2, HIGH); }\n",
        "src/examples/ignored.cpp": "int x;\n"})
    analysis = analyse_sources(root, extract_dependencies(root).environments[0], tmp_path / "w")
    assert sorted(r.file for r in analysis.parse_results) == ["src/app.ino", "src/helper.cpp"]
    assert all(r.status == "parsed" for r in analysis.parse_results)


def test_conditional_compilation_follows_build_flags(tmp_path):
    root = write_project(tmp_path / "p", {
        "platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n"
                          "build_flags = -D USE_RELAY\n",
        "src/main.cpp": "#include <Arduino.h>\nvoid setup(){\n#ifdef USE_RELAY\n pinMode(23, OUTPUT);\n#else\n"
                        " pinMode(34, OUTPUT);\n#endif\n}\nvoid loop(){}\n"})
    analysis = analyse_sources(root, extract_dependencies(root).environments[0], tmp_path / "w")
    assert [o["gpio"] for o in _ops(analysis)] == [23]


def test_compile_commands_flags_are_used(tmp_path):
    root = write_project(tmp_path / "p", {
        "platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n",
        "src/main.cpp": "#include <Arduino.h>\nvoid setup(){ pinMode(BOARD_LED, OUTPUT); }\nvoid loop(){}\n"})
    (root / "compile_commands.json").write_text(json.dumps([{
        "directory": "/home/dev/proj", "file": "/home/dev/proj/src/main.cpp",
        "command": "xtensa-esp32-elf-g++ -mlongcalls -DBOARD_LED=5 -I/home/dev/.platformio/packages/framework/cores "
                   "-c src/main.cpp"}]), encoding="utf-8")
    context = build_context(root, extract_dependencies(root).environments[0], tmp_path / "w")
    assert context.mode == "compile_commands"
    assert "-DBOARD_LED=5" in context.per_file_flags["src/main.cpp"]
    assert any("dropped" in n for n in context.notes) and any("do not exist" in n for n in context.notes)
    analysis = analyse_sources(root, extract_dependencies(root).environments[0], tmp_path / "w2")
    assert _ops(analysis)[0]["gpio"] == 5


def test_decode_c_string():
    assert decode_c_string(r'"a\nb\x41"') == "a\nbA"
    assert decode_c_string('u8"hi"') == "hi"
    assert decode_c_string('R"x(raw \\n)x"') == "raw \\n"


def test_source_code_is_not_executed(tmp_path):
    # a build script in the upload must never run
    root = write_project(tmp_path / "p", {
        "platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n"
                          "extra_scripts = pre:evil.py\n",
        "evil.py": f"open(r'{tmp_path / 'executed.txt'}', 'w').write('ran')\n",
        "src/main.cpp": "void setup(){}\nvoid loop(){}\n"})
    analyse_sources(root, extract_dependencies(root).environments[0], tmp_path / "w")
    assert not (tmp_path / "executed.txt").exists()
