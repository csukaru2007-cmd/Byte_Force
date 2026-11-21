import pytest
import requests

from backend.platformio.registry_client import (RegistryInvalidResponse, RegistryRateLimited,
                                                RegistryUnavailable)
from tests.fake_registry import FakeResponse, connection_error, make_client


def test_found_and_cached(tmp_path):
    client, session = make_client(tmp_path)
    first = client.get_package("bblanchon", "library", "ArduinoJson")
    second = client.get_package("bblanchon", "library", "ArduinoJson")
    assert first.found and first.data["name"] == "ArduinoJson" and not first.from_cache
    assert second.from_cache and len(session.calls) == 1
    assert first.retrieved_at.endswith("+00:00")


def test_url_encodes_names_with_spaces(tmp_path):
    client, session = make_client(tmp_path)
    assert client.get_package("adafruit", "library", "Adafruit BME280 Library").found
    assert "Adafruit%20BME280%20Library" in session.calls[0]


def test_not_found_is_cached_and_not_an_error(tmp_path):
    client, session = make_client(tmp_path)
    assert client.get_package("nobody", "library", "Nothing").found is False
    assert client.get_package("nobody", "library", "Nothing").from_cache
    assert len(session.calls) == 1


def test_rate_limit_retry_then_success(tmp_path):
    client, session = make_client(tmp_path)
    session.script = [FakeResponse(429, {}, headers={"Retry-After": "1"})]
    waits = []
    client.sleep = waits.append
    assert client.get_package("bblanchon", "library", "ArduinoJson").found
    assert waits == [1.0] and len(session.calls) == 2


def test_rate_limit_too_long_raises(tmp_path):
    client, session = make_client(tmp_path)
    session.script = [FakeResponse(429, {}, headers={"Retry-After": "600"})]
    with pytest.raises(RegistryRateLimited) as info:
        client.get_package("bblanchon", "library", "ArduinoJson")
    assert info.value.retry_after == 600


def test_rate_limit_exhausted_retries(tmp_path):
    client, session = make_client(tmp_path)
    session.script = [FakeResponse(429, {})] * 3
    with pytest.raises(RegistryRateLimited):
        client.get_package("bblanchon", "library", "ArduinoJson")
    assert len(session.calls) == 3


def test_network_down_trips_circuit_breaker(tmp_path):
    client, session = make_client(tmp_path)
    session.script = [connection_error()]
    with pytest.raises(RegistryUnavailable):
        client.get_package("bblanchon", "library", "ArduinoJson")
    with pytest.raises(RegistryUnavailable, match="not contacted"):
        client.get_package("knolleary", "library", "PubSubClient")
    assert len(session.calls) == 1          # second call never touched the network


def test_timeout_is_unavailable(tmp_path):
    client, session = make_client(tmp_path)
    session.script = [requests.Timeout("read timed out")]
    with pytest.raises(RegistryUnavailable, match="timed out"):
        client.get_package("bblanchon", "library", "ArduinoJson")


def test_stale_cache_used_when_registry_down(tmp_path):
    client, _ = make_client(tmp_path)
    client.get_package("bblanchon", "library", "ArduinoJson")
    later, session = make_client(tmp_path, ttl_seconds=0)
    session.script = [connection_error()]
    result = later.get_package("bblanchon", "library", "ArduinoJson")
    assert result.found and result.from_cache and result.stale


def test_invalid_json_and_invalid_structure(tmp_path):
    client, session = make_client(tmp_path)
    session.script = [FakeResponse(200, text="<html>oops</html>")]
    with pytest.raises(RegistryInvalidResponse):
        client.get_package("bblanchon", "library", "ArduinoJson")
    client2, session2 = make_client(tmp_path / "b")
    session2.script = [FakeResponse(200, {"unexpected": True})]
    with pytest.raises(RegistryInvalidResponse):
        client2.get_package("bblanchon", "library", "ArduinoJson")


def test_server_error_is_unavailable(tmp_path):
    client, session = make_client(tmp_path)
    session.script = [FakeResponse(500, {})]
    with pytest.raises(RegistryUnavailable, match="500"):
        client.get_package("bblanchon", "library", "ArduinoJson")


def test_find_by_name_exact_matches_only(tmp_path):
    client, _ = make_client(tmp_path)
    result = client.find_by_name("FastLED")
    assert sorted(i["owner"]["username"] for i in result.data) == ["fastled", "jasonlzt"]
    assert result.data[0]["owner"]["username"] == "fastled"    # most popular first
