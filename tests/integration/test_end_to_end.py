"""Acceptance: upload one complete PlatformIO project, run all three components, get one report."""

import json
import shutil

import pytest

from tests.fake_registry import connection_error, make_client, package
from tests.helpers import FIXTURES, zip_folder


@pytest.fixture
def complete_project(tmp_path):
    """A project that triggers all three components (built from the harmless fixtures)."""
    root = tmp_path / "WeatherNode"
    shutil.copytree(FIXTURES / "suspicious_indicators" / "unexpected_network_call", root)
    (root / "platformio.ini").write_text(
        "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n"
        "lib_deps =\n    adafruit/Adafruit BME280 Library @ 2.3.0\n    sensorlabs/Adafruit BME28O Library\n"
        "    nobody/MissingLib\n", encoding="utf-8")
    (root / "src" / "extra.cpp").write_text(
        '#include <Arduino.h>\n#include <WiFi.h>\n#define WIFI_PASS "FakeE2E-Password-1"\n'
        'void connect(){ WiFi.begin("Lab", WIFI_PASS); pinMode(34, OUTPUT); }\n', encoding="utf-8")
    return root


def _run(api_client, tmp_path, project, *, session_script=None, chip="ESP32-WROOM-32", registry="online"):
    client, app = api_client
    packages = None
    registry_client, session = make_client(tmp_path / "registry", packages)
    if session_script:
        session.script = list(session_script)
    app.state.scan_options = {"registry_factory": lambda: registry_client}
    response = client.post("/api/scan", files={"file": (f"{project.name}.zip", zip_folder(project), "application/zip")},
                           data={"chip": chip, "registry": registry})
    assert response.status_code == 202, response.text
    report = client.get(f"/api/scan/{response.json()['scan_id']}").json()
    assert report["status"] == "completed", report.get("error")
    return report


def test_full_scan_produces_unified_report(api_client, tmp_path, complete_project):
    report = _run(api_client, tmp_path, complete_project)
    # shape required by the specification
    for key in ("scan_id", "status", "project", "summary", "package_results", "hardware_results",
                "security_results", "errors", "risk_assessment"):
        assert key in report
    assert report["project"]["name"] == "WeatherNode" and report["project"]["chip"] == "ESP32-WROOM-32"
    assert report["summary"]["dependencies_scanned"] >= 3

    components = {f["component"] for f in report["findings"]}
    assert components == {"platformio_intelligence", "hardware_intelligence", "security_engine"}
    rules = {f["rule_id"] for f in report["findings"]}
    assert {"PKG001", "PKG003", "HW001", "NET002", "CRED001"} <= rules
    for finding in report["findings"]:
        for key in ("component", "rule_id", "category", "severity", "file", "line", "description",
                    "evidence", "recommendation", "confidence"):
            assert key in finding
    hw = next(f for f in report["hardware_results"] if f["rule_id"] == "HW001")
    assert (hw["file"], hw["line"]) == ("src/extra.cpp", 4)
    assert "FakeE2E-Password-1" not in json.dumps(report)
    risk = report["risk_assessment"]
    assert risk["score"] > 0 and risk["contributions"] and "not a probability" in risk["statement"]
    assert report["analysis"]["ast"]["files_parsed"] == 3


def test_parser_errors_and_unavailable_metadata_are_visible(api_client, tmp_path, complete_project):
    (complete_project / "src" / "broken.cpp").write_text("#include <NoSuchVendor.h>\nvoid f() { int x = ; }\n",
                                                         encoding="utf-8")
    report = _run(api_client, tmp_path, complete_project, session_script=[connection_error()])
    stages = {e["stage"] for e in report["errors"]}
    assert {"parser", "registry"} <= stages
    parser = next(e for e in report["errors"] if e["stage"] == "parser" and e["file"] == "src/broken.cpp")
    assert "NoSuchVendor.h" in json.dumps(parser)
    statuses = {r["package"]: r["metadata_status"] for r in report["package_results"]}
    assert statuses["adafruit/Adafruit BME280 Library"] == "unavailable"
    # the application stays usable: hardware and security results are still produced
    assert report["hardware_results"] and report["security_results"]
    assert report["risk_assessment"]["completeness"] == "PARTIAL"


def test_offline_registry_mode(api_client, tmp_path, complete_project):
    client, app = api_client
    app.state.scan_options = {}
    from backend import config
    original = config.CACHE_DIR
    config.CACHE_DIR = tmp_path / "empty-cache"
    try:
        response = client.post("/api/scan", files={"file": ("p.zip", zip_folder(complete_project), "application/zip")},
                               data={"registry": "offline"})
        report = client.get(f"/api/scan/{response.json()['scan_id']}").json()
    finally:
        config.CACHE_DIR = original
    assert report["status"] == "completed"
    assert report["analysis"]["registry"]["network_calls"] == 0
    assert all(r["metadata_status"] in ("unavailable", "not_applicable", "not_in_registry")
               for r in report["package_results"])


def test_benign_project_has_low_priority(api_client, tmp_path):
    project = tmp_path / "Sensor"
    shutil.copytree(FIXTURES / "benign" / "normal_sensor_project", project)
    report = _run(api_client, tmp_path, project)
    assert report["findings"] == []
    assert report["risk_assessment"]["score"] == 0 and report["risk_assessment"]["review_priority"] == "NONE"


def test_unsupported_chip_profile_reported(api_client, tmp_path, complete_project):
    report = _run(api_client, tmp_path, complete_project, chip="ESP32-C3")
    assert report["hardware_analysis"]["status"] == "skipped" and report["hardware_results"] == []
    assert any("ESP32-C3" in e["message"] for e in report["errors"])


def test_demo_scan_is_labelled(api_client, tmp_path):
    client, app = api_client
    registry_client, _ = make_client(tmp_path / "registry", [
        package("adafruit", "Adafruit BME280 Library", pkg_id=166, versions=("2.3.0",),
                repository_url="https://github.com/adafruit/Adafruit_BME280_Library.git")])
    app.state.scan_options = {"registry_factory": lambda: registry_client}
    response = client.post("/api/scan/demo")
    report = client.get(f"/api/scan/{response.json()['scan_id']}").json()
    assert report["status"] == "completed" and report["demo"] is True
    assert "DEMO" in report["project"]["name"]
    assert "HW001" in {f["rule_id"] for f in report["findings"]}


def test_profiles_and_health(api_client):
    client, _ = api_client
    profiles = client.get("/api/profiles").json()["profiles"]
    assert profiles[0]["id"] == "esp32_wroom_32" and profiles[0]["supported"]
    health = client.get("/api/health").json()
    assert health["clang"]["available"] and health["rules"]["security"] >= 20


def test_invalid_registry_mode(api_client, tmp_path, complete_project):
    client, _ = api_client
    response = client.post("/api/scan", files={"file": ("p.zip", zip_folder(complete_project), "application/zip")},
                           data={"registry": "sometimes"})
    assert response.status_code == 400


def test_frontend_is_served(api_client):
    client, _ = api_client
    page = client.get("/")
    assert page.status_code == 200 and "ShipSafe" in page.text
