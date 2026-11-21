"""Optional live checks against the real PlatformIO Registry.

    set SHIPSAFE_LIVE=1 && python -m pytest -m live
"""

import os

import pytest

from backend.platformio.ini_parser import parse_spec
from backend.platformio.package_intel import PackageAnalyser
from backend.platformio.registry_client import RegistryClient

pytestmark = [pytest.mark.live,
              pytest.mark.skipif(os.environ.get("SHIPSAFE_LIVE") != "1", reason="set SHIPSAFE_LIVE=1")]


@pytest.fixture
def live_client(tmp_path):
    return RegistryClient(cache_dir=tmp_path / "cache", ttl_seconds=0)


def test_live_metadata_for_known_package(live_client):
    result = PackageAnalyser(live_client).analyse_dependency(parse_spec("bblanchon/ArduinoJson", "lib_deps"))
    meta = result["metadata"]
    assert result["metadata_status"] == "retrieved" and result["trust_status"] == "verified_trusted"
    assert meta["registry_id"] == 64 and meta["owner"] == "bblanchon"
    assert meta["repository_url"].startswith("https://github.com/bblanchon/ArduinoJson")
    assert meta["latest_version"] and meta["versions_count"] > 10 and meta["retrieved_at"]


def test_live_unknown_package(live_client):
    result = PackageAnalyser(live_client).analyse_dependency(
        parse_spec("shipsafe-test-nobody/DefinitelyNotARealLib", "lib_deps"))
    assert result["metadata_status"] == "not_found"
    assert [f["rule_id"] for f in result["findings"]] == ["PKG003"]


def test_live_same_name_other_publisher(live_client):
    result = PackageAnalyser(live_client).analyse_dependency(parse_spec("jasonlzt/FastLED", "lib_deps"))
    assert "PKG002" in [f["rule_id"] for f in result["findings"]]
