import json

import pytest

from backend.platformio.ini_parser import (classify_source, extract_dependencies, parse_build_flags,
                                           parse_spec, split_entries)
from tests.helpers import write_project


@pytest.mark.parametrize("raw, kind, owner, name, version", [
    ("bblanchon/ArduinoJson@7.4.3", "registry_library", "bblanchon", "ArduinoJson", "7.4.3"),
    ("bblanchon/ArduinoJson @ ^7.0.0", "registry_library", "bblanchon", "ArduinoJson", "^7.0.0"),
    ("Adafruit BME280 Library", "registry_library", None, "Adafruit BME280 Library", None),
    ("knolleary/PubSubClient", "registry_library", "knolleary", "PubSubClient", None),
    ("64", "registry_legacy_id", None, "64", None),
    ("WiFi", "framework_builtin", None, "WiFi", None),
    ("HTTPClient", "framework_builtin", None, "HTTPClient", None),
])
def test_parse_registry_specs(raw, kind, owner, name, version):
    dep = parse_spec(raw, "lib_deps")
    assert (dep.kind, dep.owner, dep.name, dep.version_spec) == (kind, owner, name, version)


def test_owner_qualified_builtin_name_is_registry():
    # an owner makes it a registry package even if the bare name matches a framework library
    assert parse_spec("someone/WiFi", "lib_deps").kind == "registry_library"


@pytest.mark.parametrize("raw, pin", [
    ("https://github.com/me-no-dev/AsyncTCP.git", "unpinned"),
    ("https://github.com/adafruit/Adafruit_BME280_Library.git#2.2.4", "tag"),
    ("https://github.com/owner/repo#3f2a9c1", "commit"),
    ("https://github.com/owner/repo.git#main", "branch_or_tag"),
    ("git@github.com:owner/repo.git#v1.0.0", "tag"),
    ("git+https://example.com/owner/repo#v2", "tag"),
])
def test_git_dependencies(raw, pin):
    dep = parse_spec(raw, "lib_deps")
    assert dep.kind == "git" and dep.source == "git" and dep.git_pin == pin
    assert dep.repo_owner == "owner" or dep.repo_owner in ("me-no-dev", "adafruit")


def test_custom_named_url_and_local():
    dep = parse_spec("MyLib=https://github.com/acme/mylib.git#v1.2.0", "lib_deps")
    assert dep.custom_name == "MyLib" and dep.repo_owner == "acme" and dep.git_ref == "v1.2.0"
    assert parse_spec("file://C:/libs/foo", "lib_deps").kind == "local"
    assert parse_spec("symlink://../shared/foo", "lib_deps").kind == "local"
    assert parse_spec("../shared/foo", "lib_deps").kind == "local"


def test_archive_url():
    dep = parse_spec("https://example.com/downloads/lib-1.0.zip", "lib_deps")
    assert dep.kind == "archive_url" and dep.source == "archive"
    assert classify_source("https://github.com/o/r/archive/refs/tags/v1.zip")["kind"] == "archive_url"


def test_platform_and_tool_packages():
    plat = parse_spec("espressif32 @ 6.5.0", "platform")
    assert (plat.kind, plat.name, plat.version_spec, plat.registry_type) == ("platform", "espressif32", "6.5.0", "platform")
    url_plat = parse_spec("https://github.com/pioarduino/platform-espressif32/releases/download/54.03.20/platform-espressif32.zip", "platform")
    assert url_plat.kind == "platform" and url_plat.source == "archive"
    tool = parse_spec("platformio/framework-arduinoespressif32 @ https://github.com/espressif/arduino-esp32.git#2.0.5", "platform_packages")
    assert (tool.kind, tool.owner, tool.name, tool.source, tool.git_ref) == (
        "tool_package", "platformio", "framework-arduinoespressif32", "git", "2.0.5")
    plain_tool = parse_spec("toolchain-xtensa-esp32 @ 8.4.0+2021r2-patch5", "platform_packages")
    assert plain_tool.registry_type == "tool" and plain_tool.version_spec == "8.4.0+2021r2-patch5"


def test_split_entries_keeps_version_ranges():
    assert split_entries("a, b\n  c @ >=1.0,<2.0 ; comment\n# full comment\n") == ["a", "b", "c @ >=1.0,<2.0"]


def test_build_flags_are_parsed_not_executed():
    defines, includes, ignored, dynamic = parse_build_flags(
        ['-D LED_PIN=34 -DDEBUG', "-Iinclude/extra", "-Os", "!python get_flags.py"])
    assert defines == {"LED_PIN": "34", "DEBUG": None}
    assert includes == ["include/extra"]
    assert ignored == ["-Os"]
    assert dynamic == ["!python get_flags.py"]


INI = """
[platformio]
default_envs = esp32dev

[common]
lib_deps =
    bblanchon/ArduinoJson @ 7.4.3
    knolleary/PubSubClient

[env]
framework = arduino

[env:esp32dev]
platform = espressif32@6.5.0
board = esp32dev
lib_deps =
    ${common.lib_deps}
    WiFi
    https://github.com/me-no-dev/AsyncTCP.git
build_flags = -D LED_PIN=2 ${sysenv.SECRET}
extra_scripts = pre:patch.py
platform_packages = platformio/framework-arduinoespressif32 @ 3.20014.231204

[env:release]
extends = env:esp32dev
lib_deps = ${env:esp32dev.lib_deps}
"""


def test_extract_dependencies_full_project(tmp_path):
    root = write_project(tmp_path, {"platformio.ini": INI, "src/main.cpp": "",
                                    "lib/MyDriver/MyDriver.h": ""})
    result = extract_dependencies(root)
    by_name = {d.name: d for d in result.dependencies}
    assert by_name["ArduinoJson"].declared_in == ["esp32dev", "release"]
    assert by_name["PubSubClient"].kind == "registry_library"
    assert by_name["WiFi"].kind == "framework_builtin"
    assert by_name["AsyncTCP"].kind == "git"
    assert by_name["espressif32"].kind == "platform"
    assert by_name["framework-arduinoespressif32"].kind == "tool_package"
    assert by_name["arduino"].kind == "framework"
    assert by_name["MyDriver"].kind == "local"
    env = result.environments[0]
    assert env.board == "esp32dev" and env.defines == {"LED_PIN": "2"}
    assert result.default_envs == ["esp32dev"]
    notes = " ".join(result.notes)
    assert "extra_scripts" in notes and "sysenv.SECRET" in notes
    # release inherits board via extends
    assert result.environments[1].board == "esp32dev"


def test_installed_libdeps_are_inspected(tmp_path):
    root = write_project(tmp_path, {
        "platformio.ini": "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n"
                          "lib_deps = bblanchon/ArduinoJson@^7.0.0\n",
        ".pio/libdeps/esp32dev/ArduinoJson/.piopm": json.dumps({
            "type": "library", "name": "ArduinoJson", "version": "7.4.3",
            "spec": {"owner": "bblanchon", "id": 64, "name": "ArduinoJson", "requirements": "^7.0.0"}}),
        ".pio/libdeps/esp32dev/Adafruit BusIO/library.properties": "name=Adafruit BusIO\nversion=1.16.1\n",
    })
    result = extract_dependencies(root)
    by_name = {d.name: d for d in result.dependencies}
    assert by_name["ArduinoJson"].installed["version"] == "7.4.3"
    assert by_name["ArduinoJson"].installed["registry_id"] == 64
    transitive = by_name["Adafruit BusIO"]
    assert transitive.declared is False and transitive.installed["version"] == "1.16.1"
