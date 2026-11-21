"""Client for the public PlatformIO Registry API (https://api.registry.platformio.org/).

Endpoints used (from https://api.registry.platformio.org/v3/openapi.yaml):

    GET /v3/packages/{owner}/{type}/{name}          package details (404 = no such package)
    GET /v3/packages/{owner}/{type}/{name}/dlstats  daily download counts per version
    GET /v3/search?query=...&limit=...              package search

The OpenAPI document does not describe response bodies, so the fields this client
relies on were taken from real responses and are validated on every call. Fields
that are absent are reported as null; nothing is invented.

Behaviour:
* connect/read timeouts on every request
* HTTP 429/503: honour Retry-After up to REGISTRY_MAX_RETRY_WAIT seconds, retry a few
  times, then raise RegistryRateLimited
* other HTTP errors / network errors raise RegistryUnavailable
* after the first unavailability the client stops calling the network for the rest of
  the scan (circuit breaker) and serves cached data only, so one outage cannot stall a scan
* successful answers *and* 404s are cached on disk with a TTL; a stale cache entry is
  used (and flagged) when the registry cannot be reached
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable

import requests

from backend import config


class RegistryError(Exception):
    """Registry could not answer. This is never the same as 'package does not exist'."""

    reason = "unavailable"


class RegistryUnavailable(RegistryError):
    reason = "unavailable"


class RegistryRateLimited(RegistryError):
    reason = "rate_limited"

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class RegistryInvalidResponse(RegistryError):
    reason = "invalid_response"


@dataclass
class RegistryResult:
    found: bool                 # False => HTTP 404
    data: Any
    url: str
    retrieved_at: str           # when the registry produced this answer (UTC, ISO 8601)
    from_cache: bool = False
    stale: bool = False         # cache entry older than the TTL, used because the API failed


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
        except (TypeError, ValueError):
            return None


def validate_package(data: Any) -> dict:
    if not isinstance(data, dict):
        raise RegistryInvalidResponse("package response is not a JSON object")
    owner = data.get("owner")
    if not isinstance(data.get("name"), str) or not isinstance(owner, dict) \
            or not isinstance(owner.get("username"), str):
        raise RegistryInvalidResponse("package response lacks 'name' or 'owner.username'")
    return data


def validate_search(data: Any) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise RegistryInvalidResponse("search response lacks an 'items' list")
    for item in data["items"]:
        validate_package(item)
    return data


def validate_dlstats(data: Any) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("versions"), list):
        raise RegistryInvalidResponse("dlstats response lacks a 'versions' list")
    return data


class RegistryClient:
    def __init__(self, *, base_url: str | None = None, cache_dir: Path | None = None,
                 ttl_seconds: int | None = None, session: Any = None, offline: bool = False,
                 sleep: Callable[[float], None] = time.sleep, use_cache: bool = True):
        self.base_url = (base_url or config.REGISTRY_API).rstrip("/")
        self.cache_dir = cache_dir or config.CACHE_DIR
        self.ttl = config.CACHE_TTL_SECONDS if ttl_seconds is None else ttl_seconds
        self.session = session or requests.Session()
        self.offline = offline
        self.sleep = sleep
        self.use_cache = use_cache
        self.network_calls = 0
        self.disabled_reason: str | None = "offline mode" if offline else None

    # ------------------------------------------------------------------ cache
    def _cache_path(self, url: str) -> Path:
        return self.cache_dir / (hashlib.sha256(url.encode()).hexdigest()[:32] + ".json")

    def _cache_read(self, url: str) -> dict | None:
        if not self.use_cache:
            return None
        try:
            entry = json.loads(self._cache_path(url).read_text(encoding="utf-8"))
            return entry if entry.get("url") == url else None
        except (OSError, ValueError):
            return None

    def _cache_write(self, url: str, status: int, body: Any) -> float:
        now = time.time()
        if self.use_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            entry = {"url": url, "status": status, "fetched_at": now, "body": body}
            self._cache_path(url).write_text(json.dumps(entry), encoding="utf-8")
        return now

    # ------------------------------------------------------------------ http
    def _get(self, path: str, params: dict | None, validator: Callable[[Any], Any]) -> RegistryResult:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        cached = self._cache_read(url)
        if cached and time.time() - cached["fetched_at"] < self.ttl:
            return self._from_cache(cached, validator, stale=False)

        if self.disabled_reason:
            if cached:
                return self._from_cache(cached, validator, stale=True)
            raise RegistryUnavailable(f"registry not contacted ({self.disabled_reason})")

        try:
            response = self._request_with_retries(url)
        except RegistryError as error:
            self.disabled_reason = f"{error.reason}: {error}"
            if cached:
                return self._from_cache(cached, validator, stale=True)
            raise

        if response.status_code == 404:
            fetched = self._cache_write(url, 404, None)
            return RegistryResult(False, None, url, _iso(fetched))
        if response.status_code != 200:
            error = RegistryUnavailable(f"registry answered HTTP {response.status_code}")
            self.disabled_reason = f"{error.reason}: {error}"
            if cached:
                return self._from_cache(cached, validator, stale=True)
            raise error
        try:
            body = validator(response.json())
        except ValueError as error:  # JSON decode error
            raise RegistryInvalidResponse(f"registry returned invalid JSON: {error}") from error
        fetched = self._cache_write(url, 200, body)
        return RegistryResult(True, body, url, _iso(fetched))

    def _request_with_retries(self, url: str):
        attempts = config.REGISTRY_MAX_RETRIES + 1
        for attempt in range(attempts):
            try:
                self.network_calls += 1
                response = self.session.get(
                    url, timeout=(config.REGISTRY_CONNECT_TIMEOUT, config.REGISTRY_READ_TIMEOUT),
                    headers={"User-Agent": "ShipSafe-scanner/2.0", "Accept": "application/json"})
            except requests.Timeout as error:
                raise RegistryUnavailable(f"registry request timed out: {error}") from error
            except requests.RequestException as error:
                raise RegistryUnavailable(f"could not reach the registry: {error}") from error
            if response.status_code not in (429, 503):
                return response
            wait = _retry_after_seconds(response.headers.get("Retry-After"))
            last = attempt == attempts - 1
            if last or (wait is not None and wait > config.REGISTRY_MAX_RETRY_WAIT):
                if response.status_code == 429:
                    raise RegistryRateLimited("registry rate limit reached (HTTP 429)", retry_after=wait)
                raise RegistryUnavailable("registry temporarily unavailable (HTTP 503)")
            self.sleep(wait if wait is not None else 2 ** attempt)
        raise RegistryUnavailable("registry retries exhausted")  # pragma: no cover

    @staticmethod
    def _from_cache(entry: dict, validator, stale: bool) -> RegistryResult:
        if entry["status"] == 404:
            return RegistryResult(False, None, entry["url"], _iso(entry["fetched_at"]), True, stale)
        return RegistryResult(True, validator(entry["body"]), entry["url"], _iso(entry["fetched_at"]),
                              True, stale)

    # ------------------------------------------------------------------ endpoints
    def get_package(self, owner: str, pkg_type: str, name: str) -> RegistryResult:
        quote = urllib.parse.quote
        return self._get(f"/packages/{quote(owner, safe='')}/{pkg_type}/{quote(name, safe='')}",
                         None, validate_package)

    def get_dlstats(self, owner: str, pkg_type: str, name: str) -> RegistryResult:
        quote = urllib.parse.quote
        return self._get(f"/packages/{quote(owner, safe='')}/{pkg_type}/{quote(name, safe='')}/dlstats",
                         None, validate_dlstats)

    def search(self, query: str, limit: int = 50) -> RegistryResult:
        return self._get("/search", {"query": query, "limit": limit}, validate_search)

    def find_by_name(self, name: str, pkg_type: str = "library") -> RegistryResult:
        """Search for packages whose name is exactly `name` (case-insensitive)."""
        result = self.search(f'type:{pkg_type} "{name}"')
        if result.found:
            exact = [item for item in result.data["items"]
                     if item["name"].lower() == name.lower() and item.get("type", pkg_type) == pkg_type]
            exact.sort(key=lambda item: item.get("popularity_rank") or 10 ** 9)
            result = RegistryResult(True, exact, result.url, result.retrieved_at,
                                    result.from_cache, result.stale)
        return result
