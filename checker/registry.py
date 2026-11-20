"""Talk to the PlatformIO registry (metadata only - we never download a library).

Two endpoints are used:

    GET /v3/search?query="NAME"                    fuzzy search; we keep only exact name matches
    GET /v3/packages/<owner>/library/<name>        one package: 200 = exists, 404 = does not exist

Every answer is saved in cache.json, so running the tool twice does not hit the
network twice (and evaluation runs are repeatable and fast).
"""

import json
import urllib.parse
from pathlib import Path

import requests

API = "https://api.registry.platformio.org/v3"
CACHE_FILE = Path(__file__).resolve().parent.parent / "cache.json"
TIMEOUT_SECONDS = 20


class RegistryError(Exception):
    """The registry could not be reached. This is NOT the same as "library not found"."""


class Registry:
    def __init__(self, cache_file: Path = CACHE_FILE, offline: bool = False):
        self.cache_file = cache_file
        self.offline = offline          # offline=True: only use cache.json, never the network
        self.network_calls = 0
        try:
            self.cache = json.loads(cache_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.cache = {}

    def save(self) -> None:
        self.cache_file.write_text(json.dumps(self.cache, indent=1, sort_keys=True), encoding="utf-8")

    def _get(self, url: str, params: dict | None = None) -> dict | None:
        """GET a JSON document. Returns None for HTTP 404 (= does not exist). Cached."""
        key = url + ("?" + urllib.parse.urlencode(params) if params else "")
        if key in self.cache:
            return self.cache[key]
        if self.offline:
            raise RegistryError(f"not in cache.json and offline mode is on: {key}")
        try:
            response = requests.get(url, params=params, timeout=TIMEOUT_SECONDS,
                                    headers={"User-Agent": "shipsafe-checker"})
        except requests.RequestException as error:
            raise RegistryError(f"could not reach the registry: {error}") from error
        self.network_calls += 1
        if response.status_code == 404:
            data = None
        elif response.status_code == 200:
            data = response.json()
        else:
            # 429 / 5xx etc: do not cache, do not guess
            raise RegistryError(f"registry answered HTTP {response.status_code}")
        self.cache[key] = data
        return data

    def find_by_name(self, name: str) -> list[dict]:
        """All registry libraries whose name is exactly `name` (ignoring case), most popular first.

        Each result: {"owner": ..., "name": ..., "latest_version": ..., "popularity_rank": ...}
        """
        data = self._get(f"{API}/search", {"query": f'"{name}"', "limit": 50}) or {}
        matches = []
        for item in data.get("items", []):
            if item.get("type", "library") == "library" and item["name"].lower() == name.lower():
                matches.append({
                    "owner": item["owner"]["username"],
                    "name": item["name"],
                    "latest_version": (item.get("version") or {}).get("name"),
                    "popularity_rank": item.get("popularity_rank") or 10**9,
                })
        return sorted(matches, key=lambda m: m["popularity_rank"])

    def get_package(self, owner: str, name: str) -> dict | None:
        """Details of owner/name, or None if that exact library does not exist.

        Result: {"owner", "name", "latest_version", "versions", "headers", "repository_url"}
        """
        url = f"{API}/packages/{urllib.parse.quote(owner)}/library/{urllib.parse.quote(name)}"
        data = self._get(url)
        if data is None:
            return None
        return {
            "owner": data["owner"]["username"],
            "name": data["name"],
            "latest_version": (data.get("version") or {}).get("name"),
            "versions": [v["name"] for v in data.get("versions", [])],
            "headers": data.get("headers") or [],
            "repository_url": data.get("repository_url") or "",
        }
