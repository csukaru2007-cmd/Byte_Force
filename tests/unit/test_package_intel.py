"""The eight required PlatformIO-intelligence scenarios, with mocked registry responses."""

import json

from backend.platformio.ini_parser import extract_dependencies
from backend.platformio.package_intel import analyse_packages, load_trusted_packages
from tests.fake_registry import FakeResponse, connection_error, make_client
from tests.helpers import write_project


def _scan(tmp_path, lib_deps: str, client=None, extra_files=None):
    files = {"platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\n"
                               f"framework = arduino\nlib_deps =\n{lib_deps}\n",
             "src/main.cpp": ""}
    files.update(extra_files or {})
    root = write_project(tmp_path / "proj", files)
    client = client or make_client(tmp_path)[0]
    results, issues = analyse_packages(extract_dependencies(root), client, root)
    return {r["package"]: r for r in results}, issues


def _rules(result):
    return [f["rule_id"] for f in result["findings"]]


def test_trusted_database_is_well_formed():
    packages = load_trusted_packages()
    assert len(packages) >= 10
    for entry in packages:
        assert entry["registry_id"] and entry["registry_owner"] and entry["repository"].startswith("https://github.com/")
        assert entry["verification_source"] and entry["verified_at"]


# 1. known legitimate package
def test_known_legitimate_package(tmp_path):
    results, issues = _scan(tmp_path, "    adafruit/Adafruit BME280 Library @ 2.3.0")
    result = results["adafruit/Adafruit BME280 Library"]
    assert result["trust_status"] == "verified_trusted"
    assert result["findings"] == [] and issues == []
    meta = result["metadata"]
    assert meta["registry_id"] == 166 and meta["owner"] == "adafruit"
    assert meta["latest_version"] == "2.3.0" and meta["retrieved_at"]
    assert meta["downloads"]["total_in_window"] == 12


# 2. look-alike names
def test_lookalike_package_names(tmp_path):
    results, _ = _scan(tmp_path, "    sensorlabs/Adafruit BME28O Library\n    jsontools/ArduinoJsom @ 7.4.3")
    confusable = results["sensorlabs/Adafruit BME28O Library"]
    assert _rules(confusable) == ["PKG001"]
    finding = confusable["findings"][0]
    assert finding["severity"] == "HIGH" and finding["confidence"] == "INDICATOR"
    assert finding["details"]["matched_trusted_package"] == "Adafruit BME280 Library"
    assert "'0' replaced by 'o'" in finding["evidence"]
    assert finding["file"] == "platformio.ini" and finding["line"] == 6
    edit = results["jsontools/ArduinoJsom"]
    assert _rules(edit) == ["PKG001"] and edit["findings"][0]["severity"] == "MEDIUM"
    assert edit["similarity"]["matched_trusted_package"] == "ArduinoJson"
    assert "malicious" not in json.dumps(edit).lower()


def test_trusted_name_from_other_publisher(tmp_path):
    results, _ = _scan(tmp_path, "    jasonlzt/FastLED")
    assert _rules(results["jasonlzt/FastLED"]) == ["PKG002"]
    assert results["jasonlzt/FastLED"]["trust_status"] == "trusted_name_other_publisher"


def test_bare_name_with_several_publishers(tmp_path):
    results, _ = _scan(tmp_path, "    FastLED")
    result = results["FastLED"]
    assert "PKG004" in _rules(result)
    assert {c["owner"] for c in result["registry_candidates"]} == {"fastled", "jasonlzt"}
    assert result["trust_status"] == "verified_trusted"   # most popular candidate is the verified one


# 3. unknown package
def test_unknown_package(tmp_path):
    results, _ = _scan(tmp_path, "    nobody/TotallyMadeUpSensorLib @ 1.0.0\n    MadeUpLibraryWithoutOwner")
    assert _rules(results["nobody/TotallyMadeUpSensorLib"]) == ["PKG003"]
    assert results["nobody/TotallyMadeUpSensorLib"]["metadata_status"] == "not_found"
    assert _rules(results["MadeUpLibraryWithoutOwner"]) == ["PKG003"]


def test_unknown_package_with_lookalike_name_reports_both(tmp_path):
    results, _ = _scan(tmp_path, "    bblanch0n/ArduinoJson")
    assert set(_rules(results["bblanch0n/ArduinoJson"])) == {"PKG003"}


# 4. incomplete metadata
def test_incomplete_metadata(tmp_path):
    results, _ = _scan(tmp_path, "    someone/SparseSensorKit")
    result = results["someone/SparseSensorKit"]
    assert _rules(result) == ["PKG007"]
    assert result["metadata"]["repository_url"] is None and result["metadata"]["description"] is None
    assert result["metadata"]["homepage"] is None
    assert result["findings"][0]["details"]["missing_fields"] == ["repository_url", "description"]


def test_unpublished_version(tmp_path):
    results, _ = _scan(tmp_path, "    bblanchon/ArduinoJson @ 9.9.9")
    assert _rules(results["bblanchon/ArduinoJson"]) == ["PKG005"]


# 5. git-hosted dependency
def test_git_hosted_dependencies(tmp_path):
    client, session = make_client(tmp_path)
    results, _ = _scan(tmp_path, "    https://github.com/adafruit/Adafruit_BME280_Library.git#2.2.4\n"
                                 "    https://github.com/randomdev/ArduinoJson.git", client=client)
    upstream = results["Adafruit_BME280_Library"]
    assert upstream["trust_status"] == "verified_upstream_repository"
    assert [(f["rule_id"], f["severity"]) for f in upstream["findings"]] == [("PKG009", "INFO")]
    fork = results["ArduinoJson"]
    assert {(f["rule_id"], f["severity"]) for f in fork["findings"]} == {("PKG009", "LOW"), ("PKG006", "MEDIUM")}
    assert not any("ArduinoJson" in call and "randomdev" in call for call in session.calls)


# 6. network unavailable
def test_registry_unavailable(tmp_path):
    client, session = make_client(tmp_path)
    session.script = [connection_error()]
    results, issues = _scan(tmp_path, "    bblanchon/ArduinoJson\n    sensorlabs/Adafruit BME28O Library",
                            client=client)
    assert results["bblanchon/ArduinoJson"]["metadata_status"] == "unavailable"
    assert _rules(results["bblanchon/ArduinoJson"]) == ["PKG008"]
    # look-alike detection still works offline
    assert set(_rules(results["sensorlabs/Adafruit BME28O Library"])) == {"PKG008", "PKG001"}
    assert len(issues) == 1 and issues[0].stage == "registry"
    assert len(session.calls) == 1


# 7. API rate limit
def test_registry_rate_limited(tmp_path):
    client, session = make_client(tmp_path)
    session.script = [FakeResponse(429, {}, headers={"Retry-After": "3600"})]
    results, issues = _scan(tmp_path, "    bblanchon/ArduinoJson", client=client)
    result = results["bblanchon/ArduinoJson"]
    assert result["metadata_status"] == "unavailable" and "rate_limited" in result["metadata_error"]
    assert "rate_limited" in issues[0].message


# 8. multiple dependencies
def test_multiple_dependencies(tmp_path):
    results, _ = _scan(tmp_path, "    adafruit/Adafruit BME280 Library\n    knolleary/PubSubClient @ 2.8\n"
                                 "    jsontools/ArduinoJsom\n    WiFi\n    https://github.com/acme/lib.git#v1.0.0")
    assert results["adafruit/Adafruit BME280 Library"]["findings"] == []
    assert results["knolleary/PubSubClient"]["findings"] == []
    assert _rules(results["jsontools/ArduinoJsom"]) == ["PKG001"]
    assert results["WiFi"]["trust_status"] == "framework_component" and results["WiFi"]["findings"] == []
    assert results["espressif32"]["metadata"]["registry_id"] == 10
    assert results["arduino"]["kind"] == "framework"
    assert _rules(results["lib"]) == ["PKG009"]


def test_installed_package_mismatch(tmp_path):
    piopm = json.dumps({"type": "library", "name": "ArduinoJson", "version": "7.4.3",
                        "spec": {"owner": "bblanch0n", "id": 99999, "name": "ArduinoJson"}})
    results, _ = _scan(tmp_path, "    bblanchon/ArduinoJson @ 7.4.3",
                       extra_files={".pio/libdeps/esp32dev/ArduinoJson/.piopm": piopm})
    assert "PKG010" in _rules(results["bblanchon/ArduinoJson"])
