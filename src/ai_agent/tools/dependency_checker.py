"""ShipSafe dependency intelligence: package existence, age, popularity and typo checks.

For every Python dependency we collect evidence from public sources and turn it
into *signals*. Signals are combined into one severity per package:

    critical  - blocking condition (package does not exist / likely typosquat)
    medium    - needs human review
    outdated  - package is legitimate, but the requested version is behind the
                latest release or the project has not released in a long time
    info      - worth showing, never blocks on its own
    good      - nothing notable
    error     - the check itself failed (network, API) -> NOT the same as "good"

Existence is decided strictly from the PyPI HTTP status:
    200                       -> package exists
    404                       -> package does not exist (critical)
    429 / 5xx / network error -> unable to verify (error, never "not found")

Design rule from the project report: package age or download count *alone*
never produces a critical result. They only escalate when combined with
another signal (e.g. a name that looks like a popular package).

Data sources (metadata only - nothing is ever installed):
    * PyPI JSON API        https://pypi.org/pypi/<name>/json
    * pypistats.org        https://pypistats.org/api/packages/<name>/recent
    * top-pypi-packages    https://hugovk.dev/top-pypi-packages/

CLI:
    python -m ai_agent.tools.dependency_checker requirements.txt [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

PYPI_URL = "https://pypi.org/pypi/{name}/json"
PYPISTATS_URL = "https://pypistats.org/api/packages/{name}/recent"
TOP_PACKAGES_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
USER_AGENT = "shipsafe-dependency-checker/0.1"

CACHE_DIR = Path.home() / ".cache" / "shipsafe"
TOP_PACKAGES_CACHE = CACHE_DIR / "top-pypi-packages.json"

SEVERITY_ORDER = {"good": 0, "info": 1, "outdated": 2, "medium": 3, "critical": 4}

# PyPI existence outcomes
EXISTS, NOT_FOUND, UNVERIFIED = "exists", "not_found", "unverified"


@dataclass
class CheckerConfig:
    young_package_days: int = 90          # first release newer than this -> "young"
    stale_package_days: int = 730         # no release for this long -> "outdated" (not wrong)
    low_downloads_month: int = 1_000      # fewer downloads last month -> "low popularity"
    top_packages_limit: int = 5_000       # how many popular names to compare against
    popular_rank_exempt: int = 5_000      # a package in the top-N is never a typo suspect
    request_timeout: float = 10.0
    max_workers: int = 8
    top_packages_cache_days: int = 7
    check_downloads: bool = True


# Used when the top-packages list cannot be downloaded (offline demo, CI without network).
FALLBACK_POPULAR = [
    "boto3", "requests", "urllib3", "numpy", "pandas", "setuptools", "six", "certifi",
    "idna", "charset-normalizer", "python-dateutil", "pyyaml", "typing-extensions",
    "packaging", "cryptography", "attrs", "pydantic", "jinja2", "markupsafe", "click",
    "pip", "wheel", "pytest", "flask", "django", "fastapi", "uvicorn", "starlette",
    "sqlalchemy", "psycopg2", "psycopg2-binary", "pymysql", "redis", "celery",
    "scipy", "scikit-learn", "matplotlib", "seaborn", "pillow", "tensorflow", "torch",
    "keras", "transformers", "openai", "anthropic", "langchain", "langgraph",
    "beautifulsoup4", "lxml", "selenium", "aiohttp", "httpx", "websockets", "grpcio",
    "protobuf", "google-auth", "google-api-core", "botocore", "s3transfer", "awscli",
    "colorama", "tqdm", "rich", "python-dotenv", "pyjwt", "bcrypt", "paramiko",
    "werkzeug", "gunicorn", "pymongo", "elasticsearch", "docker", "kubernetes",
    "tornado", "jsonschema", "toml", "tomli", "filelock", "platformdirs", "virtualenv",
    "black", "flake8", "mypy", "pylint", "isort", "coverage", "pytz", "tzdata",
    "marshmallow", "pyopenssl", "requests-oauthlib", "oauthlib", "simplejson",
    "ujson", "orjson", "regex", "nltk", "opencv-python", "pyarrow", "networkx",
]


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Signal:
    code: str          # machine-readable, e.g. "PACKAGE_NOT_FOUND"
    severity: str      # critical | medium | outdated | info
    message: str       # human-readable explanation for the PR report / LLM
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Dependency:
    name: str                  # as written in the manifest
    normalized: str            # PEP 503 normalized name
    specifier: str             # e.g. "==2.0.1", ">=1.0", ""
    source_file: str
    line: int | None
    raw: str
    direct_url: str | None = None


@dataclass
class PackageResult:
    dependency: Dependency
    status: str = "ok"                    # ok | error
    severity: str = "good"                # good | info | outdated | medium | critical | error
    exists: bool | None = None
    latest_version: str | None = None
    first_release: str | None = None
    age_days: int | None = None
    release_count: int | None = None
    downloads_last_month: int | None = None
    similar_to: str | None = None
    signals: list[Signal] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, signal: Signal) -> None:
        self.signals.append(signal)

    def finalize(self) -> None:
        if self.signals:
            self.severity = max((s.severity for s in self.signals), key=SEVERITY_ORDER.__getitem__)
        if self.status == "error" and SEVERITY_ORDER.get(self.severity, 0) < SEVERITY_ORDER["critical"]:
            # We could not finish the check - never report this as "good".
            self.severity = "error"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Manifest parsing
# --------------------------------------------------------------------------- #

def normalize_name(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of -_. become a single '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _make_dependency(req_str: str, source: str, line: int | None) -> Dependency | None:
    try:
        req = Requirement(req_str)
    except InvalidRequirement:
        return None
    return Dependency(
        name=req.name,
        normalized=normalize_name(req.name),
        specifier=str(req.specifier),
        source_file=source,
        line=line,
        raw=req_str,
        direct_url=req.url,
    )


def parse_requirements_txt(path: Path, _seen: set[Path] | None = None) -> list[Dependency]:
    seen = _seen or set()
    path = path.resolve()
    if path in seen:
        return []
    seen.add(path)

    deps: list[Dependency] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")):
            included = path.parent / line.split(maxsplit=1)[1]
            if included.exists():
                deps.extend(parse_requirements_txt(included, seen))
            continue
        if line.startswith(("-e ", "--editable ")) or line.startswith(("git+", "http://", "https://")):
            deps.append(Dependency(
                name=line, normalized=line, specifier="", source_file=str(path),
                line=lineno, raw=raw, direct_url=line.split(maxsplit=1)[-1],
            ))
            continue
        if line.startswith("-"):
            continue  # other pip options (--index-url, --hash, ...)
        line = line.split(" --hash", 1)[0].rstrip(" \\")
        dep = _make_dependency(line, str(path), lineno)
        if dep:
            deps.append(dep)
    return deps


def parse_pyproject(path: Path) -> list[Dependency]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    req_strings: list[str] = list(data.get("project", {}).get("dependencies", []))
    for group in data.get("project", {}).get("optional-dependencies", {}).values():
        req_strings.extend(group)
    for group in data.get("dependency-groups", {}).values():
        req_strings.extend(r for r in group if isinstance(r, str))

    text_lines = path.read_text(encoding="utf-8").splitlines()
    deps = []
    for req in req_strings:
        lineno = next((i for i, l in enumerate(text_lines, 1) if f'"{req}"' in l or f"'{req}'" in l), None)
        dep = _make_dependency(req, str(path), lineno)
        if dep:
            deps.append(dep)
    return deps


def parse_manifest(path: str | Path) -> list[Dependency]:
    path = Path(path)
    if path.name == "pyproject.toml":
        return parse_pyproject(path)
    return parse_requirements_txt(path)


def find_manifests(repo_dir: str | Path) -> list[Path]:
    """Find supported dependency files in a repository (skips virtualenvs)."""
    repo = Path(repo_dir)
    skip = {".venv", "venv", "env", "node_modules", ".git", "site-packages", "__pycache__"}
    found = []
    for pattern in ("requirements*.txt", "pyproject.toml"):
        for p in repo.rglob(pattern):
            if not skip.intersection(p.parts):
                found.append(p)
    return sorted(found)


# --------------------------------------------------------------------------- #
# Typo / name-similarity detection
# --------------------------------------------------------------------------- #

def damerau_levenshtein(a: str, b: str, max_dist: int = 3) -> int:
    """Optimal-string-alignment distance (insert, delete, substitute, swap adjacent).

    Returns max_dist + 1 early when the strings are clearly further apart.
    """
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > max_dist:
            return max_dist + 1
        prev2, prev = prev, cur
    return prev[-1]


def _tokens_plausibly_typo(a: str, b: str) -> bool:
    """Reject matches where a shared word hides a completely different word.

    e.g. 'python-jwt' vs 'python-sat' is distance 2 overall, but 'jwt' -> 'sat'
    is a different word, not a typo. Each differing token must stay mostly intact.
    """
    ta, tb = a.split("-"), b.split("-")
    if len(ta) != len(tb) or len(ta) == 1:
        return True
    for x, y in zip(ta, tb):
        if x != y and damerau_levenshtein(x, y, 3) * 2 >= min(len(x), len(y)):
            return False
    return True


_PREFIXES = ("python3-", "python-", "py-", "py", "lib")
_SUFFIXES = ("-python3", "-python", "-py", "-dev", "-lib")


def _strip_affixes(name: str) -> list[str]:
    """Candidate base names after removing common decorative prefixes/suffixes."""
    out = []
    for p in _PREFIXES:
        if name.startswith(p) and len(name) > len(p) + 2:
            out.append(name[len(p):])
    for s in _SUFFIXES:
        if name.endswith(s) and len(name) > len(s) + 2:
            out.append(name[: -len(s)])
    return out


def find_similar_popular(name: str, popular: list[str], popular_set: set[str]) -> tuple[str, str] | None:
    """Return (popular_name, reason) if `name` looks like a misspelling of a popular package."""
    if name in popular_set:
        return None
    collapsed = name.replace("-", "")
    max_dist = 1 if len(name) <= 7 else 2

    for pop in popular:  # ordered most-downloaded first -> best match wins
        if pop == name:
            continue
        if pop.replace("-", "") == collapsed:
            return pop, "same name with different separators"
        if len(name) >= 4 and damerau_levenshtein(name, pop, max_dist) <= max_dist \
                and _tokens_plausibly_typo(name, pop):
            return pop, "edit distance"
    for stripped in _strip_affixes(name):
        if stripped in popular_set:
            return stripped, "popular name with an added prefix/suffix"
    return None


# --------------------------------------------------------------------------- #
# Data sources
# --------------------------------------------------------------------------- #

class DependencyChecker:
    def __init__(self, config: CheckerConfig | None = None, session: requests.Session | None = None):
        self.config = config or CheckerConfig()
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self._popular: list[str] | None = None
        self._popular_set: set[str] = set()
        self.popular_source = "not loaded"

    # ---- popular packages ------------------------------------------------- #
    def popular_packages(self) -> list[str]:
        if self._popular is not None:
            return self._popular
        names = self._load_cached_top() or self._download_top()
        if not names:
            names, self.popular_source = [normalize_name(n) for n in FALLBACK_POPULAR], "built-in fallback list"
        self._popular = names[: self.config.top_packages_limit]
        self._popular_set = set(self._popular[: self.config.popular_rank_exempt])
        return self._popular

    def _load_cached_top(self) -> list[str] | None:
        try:
            age = time.time() - TOP_PACKAGES_CACHE.stat().st_mtime
            if age > self.config.top_packages_cache_days * 86400:
                return None
            names = json.loads(TOP_PACKAGES_CACHE.read_text(encoding="utf-8"))
            self.popular_source = f"cache ({TOP_PACKAGES_CACHE})"
            return names
        except (OSError, ValueError):
            return None

    def _download_top(self) -> list[str] | None:
        try:
            r = self.session.get(TOP_PACKAGES_URL, timeout=self.config.request_timeout)
            r.raise_for_status()
            names = [normalize_name(row["project"]) for row in r.json()["rows"]]
        except (requests.RequestException, ValueError, KeyError):
            return None
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            TOP_PACKAGES_CACHE.write_text(json.dumps(names), encoding="utf-8")
        except OSError:
            pass
        self.popular_source = TOP_PACKAGES_URL
        return names

    # ---- remote lookups --------------------------------------------------- #
    def _get_json(self, url: str, retries: int = 2) -> tuple[int, dict | None]:
        """GET a JSON document. Returns (status, data); data is only set on HTTP 200.

        429 and 5xx are retried with backoff and, if they persist, returned as-is
        (never raised and never mistaken for 404). Network errors still raise.
        """
        status = 0
        for attempt in range(retries + 1):
            r = self.session.get(url, timeout=self.config.request_timeout)
            status = r.status_code
            if (status == 429 or status >= 500) and attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            if status == 200:
                return status, r.json()
            return status, None
        return status, None

    def fetch_pypi(self, name: str) -> tuple[str, dict | None, str | None]:
        """Look a package up on PyPI.

        Returns (outcome, metadata, reason):
            (EXISTS, meta, None)        HTTP 200
            (NOT_FOUND, None, None)     HTTP 404
            (UNVERIFIED, None, reason)  429 / 5xx / other status / network or JSON failure
        """
        try:
            status, data = self._get_json(PYPI_URL.format(name=name))
        except requests.RequestException as exc:
            return UNVERIFIED, None, f"network failure: {exc}"
        except ValueError as exc:
            return UNVERIFIED, None, f"invalid JSON from PyPI: {exc}"
        if status == 200 and data is not None:
            return EXISTS, data, None
        if status == 404:
            return NOT_FOUND, None, None
        if status == 429:
            return UNVERIFIED, None, "PyPI rate limit (HTTP 429)"
        return UNVERIFIED, None, f"PyPI returned HTTP {status}"

    def fetch_downloads(self, name: str) -> int | None:
        try:
            status, data = self._get_json(PYPISTATS_URL.format(name=name))
        except (requests.RequestException, ValueError):
            return None
        if not data:
            return None
        return data.get("data", {}).get("last_month")

    # ---- per-package analysis -------------------------------------------- #
    def check_dependency(self, dep: Dependency) -> PackageResult:
        res = PackageResult(dependency=dep)
        cfg = self.config

        if dep.direct_url:
            res.add(Signal(
                "DIRECT_URL_DEPENDENCY", "medium",
                "Dependency is installed from a URL / VCS instead of PyPI; it bypasses index "
                "checks and cannot be verified here.",
                {"url": dep.direct_url},
            ))
            res.finalize()
            return res

        popular = self.popular_packages()
        similar = find_similar_popular(dep.normalized, popular, self._popular_set)
        if similar:
            res.similar_to = similar[0]

        # 1. Existence ------------------------------------------------------
        outcome, meta, reason = self.fetch_pypi(dep.normalized)

        if outcome == UNVERIFIED:
            res.status = "error"
            res.add(Signal("UNABLE_TO_VERIFY", "medium",
                           f"Unable to verify package '{dep.name}' ({reason}). "
                           "This is NOT evidence that the package is missing - re-run the check.",
                           {"reason": reason}))
            res.errors.append(f"Unable to verify package: {reason}")
            res.finalize()
            return res

        if outcome == NOT_FOUND:
            res.exists = False
            msg = f"Package '{dep.name}' does not exist on PyPI. It may be a hallucinated name; " \
                  f"an attacker could register it (slopsquatting)."
            if similar:
                msg += f" Did you mean '{similar[0]}'?"
            res.add(Signal("PACKAGE_NOT_FOUND", "critical", msg,
                           {"similar_to": res.similar_to}))
            res.finalize()
            return res
        res.exists = True

        info = meta.get("info", {})
        releases: dict[str, list[dict]] = meta.get("releases", {}) or {}
        res.latest_version = info.get("version")
        res.release_count = sum(1 for files in releases.values() if files)

        # 2. Version --------------------------------------------------------
        self._check_version(dep, releases, res)

        # 3. Age / release history -----------------------------------------
        upload_times = [
            datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
            for files in releases.values() for f in files if f.get("upload_time_iso_8601")
        ]
        young = False
        if upload_times:
            first = min(upload_times)
            res.first_release = first.date().isoformat()
            res.age_days = (datetime.now(timezone.utc) - first).days
            young = res.age_days < cfg.young_package_days
            if young:
                res.add(Signal("YOUNG_PACKAGE", "info",
                               f"First release was only {res.age_days} days ago ({res.first_release}).",
                               {"age_days": res.age_days, "first_release": res.first_release}))
            last = max(upload_times)
            since_last = (datetime.now(timezone.utc) - last).days
            if since_last >= cfg.stale_package_days:
                res.add(Signal("STALE_PACKAGE", "outdated",
                               f"No release in {since_last} days (last: {last.date().isoformat()}). "
                               "The package is legitimate but may be unmaintained.",
                               {"days_since_last_release": since_last,
                                "last_release": last.date().isoformat()}))
        if res.release_count is not None and res.release_count <= 1:
            res.add(Signal("SINGLE_RELEASE", "info",
                           "Package has only one release - limited history to judge it by.",
                           {"release_count": res.release_count}))
        if not (info.get("project_urls") or info.get("home_page")):
            res.add(Signal("NO_PROJECT_LINKS", "info",
                           "No homepage or source repository listed on PyPI.", {}))

        # 4. Popularity -----------------------------------------------------
        low_downloads = False
        if cfg.check_downloads:
            res.downloads_last_month = self.fetch_downloads(dep.normalized)
            if res.downloads_last_month is not None and res.downloads_last_month < cfg.low_downloads_month:
                low_downloads = True
                res.add(Signal("LOW_DOWNLOADS", "info",
                               f"Only {res.downloads_last_month:,} downloads in the last month.",
                               {"downloads_last_month": res.downloads_last_month}))

        # 5. Combine signals -----------------------------------------------
        if young and low_downloads:
            res.add(Signal("NEW_AND_UNPOPULAR", "medium",
                           "Package is both new and rarely downloaded - review before trusting it.",
                           {"age_days": res.age_days, "downloads_last_month": res.downloads_last_month}))

        if similar:
            pop, reason = similar
            suspicious = young or low_downloads or (res.release_count or 0) <= 1
            established = (res.age_days or 0) >= 365 and (res.downloads_last_month or 0) >= 100_000
            if suspicious:
                sev = "critical"
            elif established and reason != "edit distance":
                sev = "info"     # e.g. 'python-jwt': mature, widely used, just a naming convention
            else:
                sev = "medium"
            msg = f"Name '{dep.name}' is very similar to the popular package '{pop}' ({reason})."
            msg += (" Combined with its young age / low popularity this looks like typosquatting."
                    if suspicious else " Confirm this is the package you intended.")
            res.add(Signal("POSSIBLE_TYPOSQUAT", sev, msg,
                           {"similar_to": pop, "reason": reason, "young": young,
                            "low_downloads": low_downloads}))

        res.finalize()
        return res

    @staticmethod
    def _check_version(dep: Dependency, releases: dict[str, list[dict]], res: PackageResult) -> None:
        if not dep.specifier:
            res.add(Signal("UNPINNED_VERSION", "info",
                           "No version constraint - builds are not reproducible.", {}))
            return
        spec = SpecifierSet(dep.specifier)
        available: list[tuple[Version, list[dict]]] = []
        for v, files in releases.items():
            try:
                available.append((Version(v), files))
            except InvalidVersion:
                continue
        matching = [(v, f) for v, f in available if spec.contains(v, prereleases=True) and f]
        if not matching:
            res.add(Signal("VERSION_NOT_FOUND", "medium",
                           f"No published version satisfies '{dep.specifier}'.",
                           {"specifier": dep.specifier, "latest": res.latest_version}))
            return

        # Outdated: the newest version the constraint allows is behind PyPI's latest.
        # The package itself is fine - report it as outdated, not as wrong.
        try:
            latest = Version(res.latest_version) if res.latest_version else None
        except InvalidVersion:
            latest = None
        best_allowed = max(v for v, _ in matching)
        if latest is not None and best_allowed < latest:
            res.add(Signal("OUTDATED_VERSION", "outdated",
                           f"'{dep.specifier}' resolves to {best_allowed} at most, but the latest "
                           f"release is {latest}. The package is legitimate; consider upgrading.",
                           {"specifier": dep.specifier, "max_allowed": str(best_allowed),
                            "latest": str(latest)}))

        pinned = [s for s in spec if s.operator in ("==", "===")]
        if pinned:
            v, files = max(matching, key=lambda x: x[0])
            if files and all(f.get("yanked") for f in files):
                reason = next((f.get("yanked_reason") for f in files if f.get("yanked_reason")), None)
                res.add(Signal("VERSION_YANKED", "medium",
                               f"Pinned version {v} was yanked from PyPI"
                               + (f": {reason}" if reason else "."),
                               {"version": str(v), "yanked_reason": reason}))

    # ---- batch entry points ---------------------------------------------- #
    def check_dependencies(self, deps: list[Dependency]) -> list[PackageResult]:
        self.popular_packages()  # load once before threads start
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as pool:
            return list(pool.map(self.check_dependency, deps))

    def check_manifest(self, path: str | Path) -> dict[str, Any]:
        return self.build_report(self.check_dependencies(parse_manifest(path)), [str(path)])

    def check_repository(self, repo_dir: str | Path) -> dict[str, Any]:
        manifests = find_manifests(repo_dir)
        deps: list[Dependency] = []
        for m in manifests:
            deps.extend(parse_manifest(m))
        return self.build_report(self.check_dependencies(deps), [str(m) for m in manifests])

    def build_report(self, results: list[PackageResult], manifests: list[str]) -> dict[str, Any]:
        counts = {k: 0 for k in ("critical", "medium", "outdated", "info", "good", "error")}
        for r in results:
            counts[r.severity] += 1
        if counts["critical"]:
            overall = "critical"
        elif counts["medium"] or counts["error"]:
            overall = "medium"   # fail-safe: a failed check requires review, not a pass
        else:
            overall = "good"
        return {
            "tool": "shipsafe-dependency-checker",
            "manifests": manifests,
            "popular_list_source": self.popular_source,
            "overall": overall,
            "counts": counts,
            "packages": [r.to_dict() for r in results],
        }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

_ICON = {"critical": "[CRITICAL]  ", "medium": "[MEDIUM]    ", "outdated": "[OUTDATED]  ",
         "info": "[INFO]      ", "good": "[OK]        ", "error": "[UNVERIFIED]"}


def format_text(report: dict[str, Any]) -> str:
    out = [f"ShipSafe dependency check - overall: {report['overall'].upper()}",
           f"Manifests: {', '.join(report['manifests']) or 'none found'}",
           f"Counts: {report['counts']}", ""]
    order = sorted(report["packages"], key=lambda p: -SEVERITY_ORDER.get(p["severity"], 5))
    for p in order:
        d = p["dependency"]
        meta = []
        if p["age_days"] is not None:
            meta.append(f"age {p['age_days']}d")
        if p["downloads_last_month"] is not None:
            meta.append(f"{p['downloads_last_month']:,} dl/month")
        if p["latest_version"]:
            meta.append(f"latest {p['latest_version']}")
        out.append(f"{_ICON.get(p['severity'], '')} {d['name']}{d['specifier']}"
                   + (f"  ({', '.join(meta)})" if meta else ""))
        for s in p["signals"]:
            if s["severity"] != "info" or p["severity"] == "info":
                out.append(f"      - {s['code']}: {s['message']}")
        for e in p["errors"]:
            out.append(f"      - ERROR: {e}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ShipSafe dependency intelligence checker")
    parser.add_argument("target", help="requirements.txt, pyproject.toml, or a repository directory")
    parser.add_argument("--json", action="store_true", help="print the full JSON report")
    parser.add_argument("--no-downloads", action="store_true", help="skip pypistats download lookups")
    args = parser.parse_args(argv)

    checker = DependencyChecker(CheckerConfig(check_downloads=not args.no_downloads))
    target = Path(args.target)
    report = checker.check_repository(target) if target.is_dir() else checker.check_manifest(target)
    print(json.dumps(report, indent=2) if args.json else format_text(report))
    return {"good": 0, "medium": 2, "critical": 1}[report["overall"]]


if __name__ == "__main__":
    sys.exit(main())
