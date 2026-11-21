"""Security pattern engine: each category is tested for detection, location and false positives."""

import json

import pytest

from backend.security_engine.base import redact, redact_url
from backend.security_engine.engine import run_security_engine
from backend.security_engine.network_detector import endpoint_of
from backend.security_engine.obfuscation_detector import encoding_of
from backend.security_engine.rule_loader import RuleCatalogError, parse_catalog, security_rules
from tests.helpers import analyse_fixture, line_of, write_project


def _scan(name, tmp_path, package_results=None):
    root, _, analysis = analyse_fixture(name, tmp_path)
    findings, issues, summary = run_security_engine(analysis.features, root, package_results)
    return root, findings, issues


def _at(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


# ------------------------------------------------------------------ rule catalog

def test_rule_catalog_is_complete():
    catalog = security_rules()
    ids = {r.rule_id for r in catalog}
    for prefix in ("NET", "CRED", "EXEC", "FW", "OBF"):
        assert any(i.startswith(prefix) for i in ids)
    for rule in catalog:
        assert rule.explanation and rule.recommendation and rule.detection_condition
        assert isinstance(rule.limitations, list)


def test_rule_catalog_validation():
    with pytest.raises(RuleCatalogError, match="missing"):
        parse_catalog({"component": "security_engine", "rules": [{"rule_id": "X1"}]}, __import__("pathlib").Path("x.json"))


# ------------------------------------------------------------------ A. network

def test_unexpected_network_call_in_dependency(tmp_path):
    root, findings, _ = _scan("suspicious_indicators/unexpected_network_call", tmp_path)
    line = line_of(root, "lib/TempProbe/src/TempProbe.cpp", "client.connect(")
    [net002] = _at(findings, "NET002")
    assert (net002.file, net002.line, net002.severity) == ("lib/TempProbe/src/TempProbe.cpp", line, "MEDIUM")
    assert net002.origin == "dependency:TempProbe"
    assert "temperature" in net002.explanation.lower()        # cites the stated purpose
    [net003] = _at(findings, "NET003")
    assert net003.severity == "MEDIUM" and "203.0.113.50" in net003.evidence and "documentation range" in net003.evidence
    assert not _at(findings, "NET001")


def test_network_library_with_matching_purpose_is_info(tmp_path):
    results = [{"package": "acme/TempProbe", "dependency": {"name": "TempProbe"},
                "metadata": {"description": "Temperature probe with MQTT cloud upload", "keywords": ["iot"]}}]
    root = analyse_fixture("suspicious_indicators/unexpected_network_call", tmp_path)[0]
    # registry metadata takes precedence over the local manifest
    (root / "lib" / "TempProbe" / "library.properties").unlink()
    from backend.ast_engine.runner import analyse_sources
    from backend.platformio.ini_parser import extract_dependencies
    analysis = analyse_sources(root, extract_dependencies(root).environments[0], tmp_path / "w2")
    findings, _, _ = run_security_engine(analysis.features, root, results)
    [net001] = _at(findings, "NET001")
    assert net001.severity == "INFO" and "consistent with its stated purpose" in net001.explanation
    assert not _at(findings, "NET002")


def test_dependency_with_unknown_purpose_is_low(tmp_path):
    root = analyse_fixture("suspicious_indicators/unexpected_network_call", tmp_path)[0]
    (root / "lib" / "TempProbe" / "library.properties").unlink()
    from backend.ast_engine.runner import analyse_sources
    from backend.platformio.ini_parser import extract_dependencies
    analysis = analyse_sources(root, extract_dependencies(root).environments[0], tmp_path / "w2")
    findings, _, _ = run_security_engine(analysis.features, root)
    [net001] = _at(findings, "NET001")
    assert net001.severity == "LOW" and "purpose is unknown" in net001.explanation


def test_ordinary_networking_is_not_treated_as_malware(tmp_path):
    for name in ("benign/normal_wifi_project", "benign/normal_sensor_project", "benign/normal_ota_project"):
        _, findings, _ = _scan(name, tmp_path / name.replace("/", "_"))
        assert all(f.severity in ("INFO", "LOW") for f in findings), [(f.rule_id, f.severity) for f in findings]
        text = json.dumps([f.to_dict() for f in findings]).lower()
        assert "malware" not in text and "malicious" not in text
    _, wifi, _ = _scan("benign/normal_wifi_project", tmp_path / "again")
    assert {f.rule_id for f in wifi} <= {"NET001", "NET003"} and all(f.severity == "INFO" for f in wifi)


def test_tls_verification_disabled(tmp_path):
    root, findings, _ = _scan("suspicious_indicators/firmware_operations", tmp_path)
    [net005] = _at(findings, "NET005")
    assert net005.line == line_of(root, "src/main.cpp", "insecureClient.setInsecure()")


# ------------------------------------------------------------------ B. credentials

def test_hardcoded_credentials(tmp_path):
    root, findings, _ = _scan("suspicious_indicators/hardcoded_test_credential", tmp_path)
    main = "src/main.cpp"
    cred001 = {f.line: f for f in _at(findings, "CRED001")}
    macro_line = line_of(root, main, "#define WIFI_PASSWORD")
    assert cred001[macro_line].evidence == '#define WIFI_PASSWORD "Fa******** (22 chars)"'
    assert any("WiFi.begin" in use for use in cred001[macro_line].details["uses"])
    auth_line = line_of(root, main, "setAuthorization")
    assert auth_line in cred001 and "HTTPClient::setAuthorization" in cred001[auth_line].description
    [cred002] = _at(findings, "CRED002")
    assert cred002.line == line_of(root, main, "api_token =") and cred002.details["format"] == "Stripe key"
    [cred003] = _at(findings, "CRED003")
    assert cred003.line == line_of(root, main, "Serial.println(WIFI_PASSWORD)")
    # empty and placeholder values, and the non-secret SSID, are not reported
    reported_lines = {f.line for f in findings if f.category == "CREDENTIAL_EXPOSURE"}
    for needle in ("password_hint", "mqtt_password", "const char *ssid", "Connecting with password"):
        assert line_of(root, main, needle) not in reported_lines, needle


def test_secrets_never_appear_in_findings(tmp_path):
    _, findings, _ = _scan("suspicious_indicators/hardcoded_test_credential", tmp_path)
    text = json.dumps([f.to_dict() for f in findings])
    for secret in ("FakePass-For-Tests-123", "sk_test_FAKE000000000000", "FakeAdminPass-0000"):
        assert secret not in text
        assert secret[2:10] not in text


def test_variable_named_password_without_literal_is_not_reported(tmp_path):
    _, findings, _ = _scan("benign/normal_wifi_project", tmp_path)
    assert not [f for f in findings if f.category == "CREDENTIAL_EXPOSURE"]


def test_redaction_helpers():
    assert redact("hunter2secret") == "hu******** (13 chars)"
    assert redact("abc") == "*** (3 chars)"
    assert redact_url("https://x.example/api?token=abcdef123&city=Oslo") == "https://x.example/api?token=ab*******&city=Oslo"


def test_secret_in_url_query(tmp_path):
    root = write_project(tmp_path / "p", {
        "platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n",
        "src/main.cpp": '#include <HTTPClient.h>\nvoid setup(){ HTTPClient h; h.begin("http://api.example.com/v1?apikey=Zx81kLmQ"); }\nvoid loop(){}\n'})
    from backend.ast_engine.runner import analyse_sources
    from backend.platformio.ini_parser import extract_dependencies
    analysis = analyse_sources(root, extract_dependencies(root).environments[0], tmp_path / "w")
    findings, _, _ = run_security_engine(analysis.features, root)
    rules = {f.rule_id for f in findings}
    assert {"CRED004", "NET004", "NET003"} <= rules
    assert "Zx81kLmQ" not in json.dumps([f.to_dict() for f in findings])


# ------------------------------------------------------------------ C. dynamic execution

def test_dynamic_execution(tmp_path):
    root, findings, issues = _scan("suspicious_indicators/dynamic_execution", tmp_path)
    cast_line = line_of(root, "src/main.cpp", "(entry_fn)codeBuffer")
    [exec003] = _at(findings, "EXEC003")
    assert exec003.line == cast_line and exec003.severity == "HIGH"
    [exec002] = _at(findings, "EXEC002")
    assert exec002.line == cast_line and "client.read()" in exec002.details["flow"]
    assert {f.line for f in _at(findings, "EXEC001")} == {line_of(root, "src/main.cpp", "dlopen("),
                                                          line_of(root, "src/main.cpp", "dlsym(")}
    assert any("function pointers or callbacks" in i.message for i in issues)


def test_no_execution_findings_in_benign_code(tmp_path):
    for name in ("benign/normal_wifi_project", "benign/normal_ota_project"):
        _, findings, _ = _scan(name, tmp_path / name.replace("/", "_"))
        assert not [f for f in findings if f.category == "DYNAMIC_EXECUTION"]


# ------------------------------------------------------------------ D. firmware

def test_firmware_operations(tmp_path):
    root, findings, _ = _scan("suspicious_indicators/firmware_operations", tmp_path)
    main = "src/main.cpp"
    lines = {f.rule_id: f.line for f in findings}
    assert lines["FW002"] == line_of(root, main, "ArduinoOTA.begin()")
    assert lines["FW003"] == line_of(root, main, "httpUpdate.update(")
    fw003 = _at(findings, "FW003")[0]
    assert "plain HTTP" in fw003.evidence and "setInsecure" in fw003.evidence
    assert lines["FW004"] == line_of(root, main, "esp_flash_erase_region")
    assert lines["FW005"] == line_of(root, main, "esp_efuse_write_field_bit")
    assert _at(findings, "FW005")[0].severity == "HIGH"
    assert lines["FW006"] == line_of(root, main, "esp_ota_set_boot_partition")


def test_legitimate_ota_is_info_only(tmp_path):
    _, findings, _ = _scan("benign/normal_ota_project", tmp_path)
    assert {f.rule_id for f in findings} == {"FW001"}
    assert all(f.severity == "INFO" for f in findings)


# ------------------------------------------------------------------ E. obfuscation

def test_encoded_data_flowing_into_firmware_write(tmp_path):
    root, findings, _ = _scan("suspicious_indicators/suspicious_encoded_data", tmp_path)
    [obf001] = _at(findings, "OBF001")
    assert obf001.severity == "INFO" and obf001.details["encoding"] == "base64"
    [obf004] = _at(findings, "OBF004")
    assert obf004.line == line_of(root, "src/main.cpp", "Update.write(decoded")
    assert "mbedtls_base64_decode" in obf004.details["flow"] and obf004.severity == "HIGH"


def _project(tmp_path, code):
    root = write_project(tmp_path / "p", {
        "platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n",
        "src/main.cpp": code})
    from backend.ast_engine.runner import analyse_sources
    from backend.platformio.ini_parser import extract_dependencies
    analysis = analyse_sources(root, extract_dependencies(root).environments[0], tmp_path / "w")
    return run_security_engine(analysis.features, root)[0]


def test_encoded_data_alone_is_only_info(tmp_path):
    cert = "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYDVQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoXDTI1MDUxMjIzNTkwMFow"
    findings = _project(tmp_path, f'#include <Arduino.h>\nconst char ROOT_CA[] = "{cert}";\nvoid setup(){{ Serial.println(ROOT_CA); }}\nvoid loop(){{}}\n')
    assert [(f.rule_id, f.severity) for f in findings] == [("OBF001", "INFO")]


def test_large_array_alone_is_only_info(tmp_path):
    values = ", ".join(f"0x{i % 256:02x}" for i in range(600))
    findings = _project(tmp_path, f"#include <Arduino.h>\nconst uint8_t FONT[] = {{{values}}};\nvoid setup(){{}}\nvoid loop(){{}}\n")
    assert [(f.rule_id, f.severity) for f in findings] == [("OBF002", "INFO")]


def test_decode_and_sensitive_operation_without_flow(tmp_path):
    findings = _project(tmp_path, "#include <Arduino.h>\n#include <Update.h>\n#include <mbedtls/base64.h>\n"
                                  "uint8_t img[64]; unsigned char cfg[32]; size_t n;\n"
                                  "void f(const unsigned char *b64){\n mbedtls_base64_decode(cfg, 32, &n, b64, 8);\n"
                                  " Update.begin(64);\n Update.write(img, 64);\n}\nvoid setup(){}\nvoid loop(){}\n")
    assert "OBF003" in {f.rule_id for f in findings} and "OBF004" not in {f.rule_id for f in findings}


def test_detector_helpers():
    assert endpoint_of("http://example.com/x")["scheme"] == "http"
    assert endpoint_of("203.0.113.9")["note"] == "documentation range"
    assert endpoint_of("192.168.1.10")["note"] == "private network"
    assert endpoint_of("hello world") is None
    assert encoding_of("ab" * 100, 128) == "hexadecimal"
    assert encoding_of("ThisIsJustAVeryLongIdentifierNameWithoutAnyDigitsOrSymbolsRepeated" * 3, 128) is None
