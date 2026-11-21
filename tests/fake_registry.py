"""A fake requests.Session for the PlatformIO Registry.

Response bodies mirror the structure of real api.registry.platformio.org/v3 responses
(field names and nesting were copied from live responses; values are trimmed).
"""

from __future__ import annotations

import json
import urllib.parse

import requests


def package(owner: str, name: str, *, pkg_id: int = 1000, versions=("1.0.0",), repository_url="auto",
            description="A library", pkg_type="library", keywords=None) -> dict:
    if repository_url == "auto":
        repository_url = f"https://github.com/{owner}/{name.replace(' ', '_')}.git"
    version_objs = [{"id": i, "name": v, "released_at": "2025-01-01T00:00:00Z", "files": [], "is_latest": i == len(versions) - 1}
                    for i, v in enumerate(versions)]
    return {
        "id": pkg_id, "type": pkg_type, "tier": "community", "name": name, "description": description,
        "owner": {"username": owner, "firstname": owner.title(), "lastname": None, "is_org": True},
        "added_at": "2016-08-16T18:31:42Z", "updated_at": "2025-04-30T13:31:16Z",
        "repository_url": repository_url, "homepage": None, "license": None,
        "keywords": keywords or ["sensors"], "frameworks": ["arduino"], "platforms": ["*"],
        "popularity_rank": pkg_id, "stars_count": 10, "dependents_count": 1,
        "version": version_objs[-1] if version_objs else None, "versions": version_objs,
        "headers": [name.replace(" ", "_") + ".h"],
    }


class FakeResponse:
    def __init__(self, status_code: int, body=None, headers=None, text=None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.text = text if text is not None else json.dumps(body)

    def json(self):
        return json.loads(self.text)


class FakeSession:
    """Routes: {(owner, type, name): package_dict} plus search results by name.

    `script` lets a test queue special responses (exceptions, 429...) for the next calls.
    """

    def __init__(self, packages: list[dict] | None = None):
        self.packages = {}
        for pkg in packages or []:
            self.add(pkg)
        self.calls: list[str] = []
        self.script: list = []

    def add(self, pkg: dict) -> None:
        self.packages[(pkg["owner"]["username"].lower(), pkg["type"], pkg["name"].lower())] = pkg

    def get(self, url, timeout=None, headers=None):
        assert timeout is not None, "registry requests must always have a timeout"
        self.calls.append(url)
        if self.script:
            item = self.script.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        parsed = urllib.parse.urlparse(url)
        parts = [urllib.parse.unquote(p) for p in parsed.path.split("/") if p]
        # /v3/packages/<owner>/<type>/<name>[/dlstats]
        if len(parts) >= 5 and parts[1] == "packages":
            key = (parts[2].lower(), parts[3], parts[4].lower())
            pkg = self.packages.get(key)
            if pkg is None:
                return FakeResponse(404, {"message": "Not found"})
            if len(parts) == 6 and parts[5] == "dlstats":
                return FakeResponse(200, {"versions": [{"name": pkg["versions"][-1]["name"] if pkg["versions"] else "1.0.0",
                                                         "daily": {"2026-11-01": 5, "2026-11-02": 7}}]})
            return FakeResponse(200, pkg)
        if len(parts) >= 2 and parts[1] == "search":
            query = urllib.parse.parse_qs(parsed.query)["query"][0]
            wanted = query.split('"')[1].lower() if '"' in query else query.lower()
            items = [p for p in self.packages.values() if p["name"].lower() == wanted]
            return FakeResponse(200, {"items": items, "page": 1, "limit": 50, "total": len(items)})
        return FakeResponse(404, {})


def default_packages() -> list[dict]:
    return [
        package("adafruit", "Adafruit BME280 Library", pkg_id=166, versions=("2.2.4", "2.3.0"),
                repository_url="https://github.com/adafruit/Adafruit_BME280_Library.git"),
        package("adafruit", "Adafruit Unified Sensor", pkg_id=31, versions=("1.1.14",),
                repository_url="https://github.com/adafruit/Adafruit_Sensor.git"),
        package("bblanchon", "ArduinoJson", pkg_id=64, versions=("6.21.3", "7.4.3"),
                repository_url="https://github.com/bblanchon/ArduinoJson.git"),
        package("knolleary", "PubSubClient", pkg_id=89, versions=("2.8",),
                repository_url="https://github.com/knolleary/pubsubclient.git"),
        # look-alikes / forks used by the suspicious fixtures
        package("sensorlabs", "Adafruit BME28O Library", pkg_id=90001, versions=("1.0.0",)),
        package("jsontools", "ArduinoJsom", pkg_id=90002, versions=("7.4.3",)),
        package("jasonlzt", "FastLED", pkg_id=90003, versions=("3.6.0",)),
        package("fastled", "FastLED", pkg_id=126, versions=("3.6.0",), repository_url="https://github.com/FastLED/FastLED.git"),
        package("someone", "SparseSensorKit", pkg_id=90004, versions=("0.1.0",), repository_url=None, description=None),
        package("platformio", "espressif32", pkg_id=10, versions=("6.5.0",), pkg_type="platform",
                repository_url="https://github.com/platformio/platform-espressif32.git"),
    ]


def make_client(tmp_path, packages=None, **kwargs):
    from backend.platformio.registry_client import RegistryClient

    session = FakeSession(default_packages() if packages is None else packages)
    client = RegistryClient(session=session, cache_dir=tmp_path / "cache", sleep=lambda s: None, **kwargs)
    return client, session


def connection_error():
    return requests.ConnectionError("network is unreachable")
