"""ShipSafe known-vulnerability scanner: pip-audit over the repo's Python dependencies.

What it answers: "does any dependency version this repo will install have a
published security advisory?" (report section 5, "Known vulnerable dependency").
Whether a package is *trustworthy* (exists, typosquat, age, popularity) is the
job of dependency_checker.py - pip-audit cannot tell, and reports a package
that does not exist as "no known vulnerabilities".

Nothing is ever installed. pip-audit normally resolves a requirements file by
pip-installing it into a temporary virtualenv, which can execute an sdist's
build code - unacceptable for untrusted / AI-generated manifests. Instead we
build an exact `name==version` list ourselves and run pip-audit with
`--no-deps --disable-pip`, which only queries the advisory database:

    pinned       - `pkg==1.2.3` in requirements*.txt / pyproject.toml
    lockfile     - every registry package in uv.lock (exact + transitive);
                   a pyproject.toml next to a uv.lock is taken from the lock
    latest-allowed - an unpinned requirement (`flask>=2.0`) is audited at the
                   newest non-yanked PyPI release its specifier allows, i.e.
                   what a fresh install would get (PyPI JSON metadata only)

Anything that cannot be matched to an advisory (direct URL / VCS / editable
requirement, package missing from PyPI, lookup failure) is listed under
`unaudited` - never silently treated as clean.

Advisory severity comes from the GitHub advisory (GHSA) rating via the OSV API:
    critical  - any advisory rated CRITICAL or HIGH
    medium    - MODERATE, or rating unknown (fail-safe: needs review)
    info      - only LOW-rated advisories
One finding per vulnerable (package, version), carrying every advisory, the
smallest version that fixes all of them, and a remediation hint.

The overall result is fail-safe (report section 13): a pip-audit failure or any
unaudited dependency yields at least "medium", never "good".

CLI:
    python -m ai_agent.tools.pip_audit_scanner <repo_dir_or_manifest> [--json]
        [--service osv|pypi] [--no-lockfiles] [--no-resolve] [--ignore-vuln ID ...]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import requests
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ai_agent.tools.code_scanner import (
    EXCLUDED_DIRS,
    SEVERITY_ORDER,
    Finding,
    ToolRun,
    _parse_json_stdout,
    _rel,
    _run,
    _snippet,
    _tool_version,
)
from ai_agent.tools.dependency_checker import PYPI_URL, Dependency, normalize_name, parse_manifest

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

SERVICES = ("osv", "pypi")
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
OSV_PAGE_URL = "https://osv.dev/vulnerability/{id}"
USER_AGENT = "shipsafe-pip-audit-scanner/0.1"

# GHSA "database_specific.severity" -> ShipSafe severity. Unknown -> medium (review).
_ADVISORY_SEVERITY = {"CRITICAL": "critical", "HIGH": "critical", "MODERATE": "medium",
                      "MEDIUM": "medium", "LOW": "info"}
_ADVISORY_RANK = {"UNKNOWN": 0, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_RESOLVED_RANK = {"pinned": 0, "lockfile": 1, "latest-allowed": 2}

# First two lines of every package block in uv.lock - used to report line numbers.
_LOCK_HEADER = re.compile(r'^\[\[package\]\]\s*\r?\nname = "([^"]+)"', re.MULTILINE)


@dataclass
class PipAuditConfig:
    service: str = "osv"                    # osv (broader: PYSEC + GHSA) | pypi
    use_lockfiles: bool = True              # audit uv.lock (exact + transitive versions)
    resolve_unpinned: bool = True           # audit unpinned reqs at newest allowed PyPI version
    enrich_severity: bool = True            # fetch GHSA severity ratings from OSV
    ignore_vulns: list[str] = field(default_factory=list)   # reviewed exceptions (IDs)
    timeout_seconds: int = 600
    request_timeout: float = 15.0
    max_workers: int = 8
    context_lines: int = 1                  # manifest lines around the dependency
    max_snippet_chars: int = 600
    excluded_dirs: list[str] = field(default_factory=lambda: list(EXCLUDED_DIRS))


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class AuditTarget:
    """One exact package version, and where in the repo it comes from."""
    package: str                            # PEP 503 normalized
    version: str                            # canonical (packaging.Version) string
    file: str                               # repo-relative manifest path
    line: int
    requirement: str                        # as written, for the report
    resolved_from: str                      # pinned | lockfile | latest-allowed
    direct: bool = True
    required_by: list[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    id: str                                 # e.g. PYSEC-2023-74 / GHSA-...
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    fix_versions: list[str] = field(default_factory=list)
    advisory_severity: str = "UNKNOWN"      # CRITICAL | HIGH | MODERATE | LOW | UNKNOWN
    severity: str = "medium"                # ShipSafe: critical | medium | info
    cwe: list[str] = field(default_factory=list)
    url: str = ""

    @property
    def display_id(self) -> str:
        """CVE id when there is one - the id people search for."""
        return next((a for a in self.aliases if a.startswith("CVE-")), self.id)


@dataclass
class VulnerableDependencyFinding(Finding):
    package: str = ""
    installed_version: str = ""
    resolved_from: str = ""                 # pinned | lockfile | latest-allowed
    direct: bool = True
    required_by: list[str] = field(default_factory=list)
    requirement: str = ""
    manifests: list[str] = field(default_factory=list)       # every "file:line" bringing it in
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    fix_version: str | None = None          # smallest version fixing every fixable advisory
    unfixed: list[str] = field(default_factory=list)          # advisory ids with no fixed release
    severity_reasons: list[str] = field(default_factory=list)
    remediation: str = ""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _version(text: str) -> Version | None:
    try:
        return Version(text)
    except (InvalidVersion, TypeError):
        return None


def _canon(text: str) -> str:
    v = _version(text)
    return str(v) if v else text


def _exact_pin(specifier: str) -> str | None:
    """'==2.0.1' -> '2.0.1'; anything that allows more than one version -> None."""
    try:
        specs = list(SpecifierSet(specifier))
    except InvalidSpecifier:
        return None
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        return specs[0].version
    return None


def find_manifests(root: Path, excluded: list[str]) -> list[Path]:
    """requirements*.txt, pyproject.toml and uv.lock, without descending into excluded dirs."""
    skip = set(excluded)
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            if fn in ("pyproject.toml", "uv.lock") or (fn.startswith("requirements") and fn.endswith(".txt")):
                found.append(Path(dirpath) / fn)
    return sorted(found)


def _batches(pins: list[tuple[str, str]]) -> list[list[tuple[str, str]]]:
    """Split pins so no package name appears twice in one requirements file (pip-audit rejects it)."""
    by_name: dict[str, list[str]] = defaultdict(list)
    for name, ver in pins:
        by_name[name].append(ver)
    depth = max((len(v) for v in by_name.values()), default=0)
    return [[(n, vs[i]) for n, vs in by_name.items() if i < len(vs)] for i in range(depth)]


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class PipAuditScanner:
    def __init__(self, config: PipAuditConfig | None = None):
        self.cfg = config or PipAuditConfig()
        if self.cfg.service not in SERVICES:
            raise ValueError(f"service must be one of {SERVICES}")
        self.version: str | None = None
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT

    # ----- dependency collection ----------------------------------------- #

    def _collect(self, root: Path, manifests: list[Path]
                 ) -> tuple[list[AuditTarget], list[tuple[Dependency, str]], list[dict[str, Any]]]:
        """Returns (exact targets, unpinned deps to resolve, unaudited entries)."""
        targets: list[AuditTarget] = []
        unpinned: list[tuple[Dependency, str]] = []
        unaudited: list[dict[str, Any]] = []
        lock_dirs = {m.parent for m in manifests if m.name == "uv.lock"} if self.cfg.use_lockfiles else set()

        for m in manifests:
            rel = _rel(str(m), root)
            if m.name == "uv.lock":
                if self.cfg.use_lockfiles:
                    self._collect_lock(m, root, targets, unaudited)
                continue
            if m.name == "pyproject.toml" and m.parent in lock_dirs:
                continue        # exact versions come from the lockfile instead
            try:
                deps = parse_manifest(m)
            except (OSError, ValueError) as exc:     # incl. TOML / Unicode decode errors
                unaudited.append({"package": None, "requirement": None, "file": rel, "line": None,
                                  "reason": f"could not parse manifest: {exc}"})
                continue
            for dep in deps:
                self._classify(dep, root, targets, unpinned, unaudited)
        return targets, unpinned, unaudited

    def _classify(self, dep: Dependency, root: Path, targets: list[AuditTarget],
                  unpinned: list[tuple[Dependency, str]], unaudited: list[dict[str, Any]]) -> None:
        rel = _rel(dep.source_file, root)
        entry = {"package": dep.normalized, "requirement": dep.raw.strip(), "file": rel, "line": dep.line}
        if dep.direct_url:
            unaudited.append({**entry, "reason": "direct URL / VCS / editable requirement - "
                                                 "cannot be matched to PyPI advisories"})
            return
        pin = _exact_pin(dep.specifier)
        if pin:
            targets.append(AuditTarget(dep.normalized, _canon(pin), rel, dep.line or 0,
                                       dep.raw.strip(), "pinned"))
        elif self.cfg.resolve_unpinned:
            unpinned.append((dep, rel))
        else:
            unaudited.append({**entry, "reason": "not pinned to an exact version (resolution disabled)"})

    def _collect_lock(self, lock: Path, root: Path, targets: list[AuditTarget],
                      unaudited: list[dict[str, Any]]) -> None:
        rel = _rel(str(lock), root)
        try:
            text = lock.read_text(encoding="utf-8")
            packages = tomllib.loads(text).get("package", [])
        except (OSError, ValueError) as exc:
            unaudited.append({"package": None, "requirement": None, "file": rel, "line": None,
                              "reason": f"could not parse lockfile: {exc}"})
            return
        lines = {normalize_name(m.group(1)): text.count("\n", 0, m.start()) + 2   # the `name =` line
                 for m in _LOCK_HEADER.finditer(text)}

        # The project itself (editable / virtual source) is the root of the graph.
        roots = {normalize_name(p["name"]) for p in packages
                 if {"editable", "virtual"} & set(p.get("source", {}))}
        parents: dict[str, set[str]] = defaultdict(set)
        for p in packages:
            groups = [p.get("dependencies", [])]
            for extra in (p.get("optional-dependencies", {}), p.get("dev-dependencies", {})):
                groups.extend(extra.values())
            for group in groups:
                for d in group:
                    parents[normalize_name(d["name"])].add(normalize_name(p["name"]))

        # Direct dependencies are reported against the pyproject.toml line people edit.
        direct_lines: dict[str, tuple[str, int, str]] = {}
        pyproject = lock.parent / "pyproject.toml"
        if pyproject.is_file():
            try:
                for d in parse_manifest(pyproject):
                    direct_lines.setdefault(d.normalized, (_rel(str(pyproject), root), d.line or 0, d.raw))
            except (OSError, ValueError):
                pass

        for p in packages:
            name = normalize_name(p["name"])
            source = p.get("source", {})
            if name in roots:
                continue
            ver = str(p.get("version") or "")
            direct = bool(parents[name] & roots) or name in direct_lines
            if "registry" not in source or not ver:
                unaudited.append({"package": name, "requirement": f"{name} {ver}".strip(), "file": rel,
                                  "line": lines.get(name),
                                  "reason": f"locked from a non-registry source {sorted(source)} - "
                                            "cannot be matched to PyPI advisories"})
                continue
            if name in direct_lines:
                file, line, raw = direct_lines[name]
                requirement = f"{raw}  (locked at {ver} in {rel})"
            else:
                file, line, requirement = rel, lines.get(name, 0), f"{name}=={ver} (transitive, {rel})"
            targets.append(AuditTarget(name, _canon(ver), file, line, requirement, "lockfile",
                                       direct=direct, required_by=sorted(parents[name] - roots)[:8]))

    # ----- unpinned -> newest allowed version (metadata only) ------------ #

    def _latest_allowed(self, dep: Dependency) -> tuple[str | None, str | None]:
        try:
            resp = self.session.get(PYPI_URL.format(name=dep.normalized), timeout=self.cfg.request_timeout)
        except requests.RequestException as exc:
            return None, f"PyPI lookup failed ({exc.__class__.__name__}) - unable to verify"
        if resp.status_code == 404:
            return None, "package not found on PyPI (see dependency checker)"
        if resp.status_code != 200:
            return None, f"PyPI returned HTTP {resp.status_code} - unable to verify"
        try:
            releases = resp.json().get("releases", {})
        except ValueError:
            return None, "PyPI returned invalid JSON"
        versions = [v for v, files in releases.items()
                    if files and not all(f.get("yanked") for f in files)]
        parsed = [p for p in map(_version, versions) if p is not None]
        try:
            allowed = list(SpecifierSet(dep.specifier).filter(parsed))
        except InvalidSpecifier:
            return None, f"invalid version specifier {dep.specifier!r}"
        if not allowed:
            return None, f"no released version satisfies {dep.specifier or '(any)'!r}"
        return str(max(allowed)), None

    def _resolve_unpinned(self, unpinned: list[tuple[Dependency, str]], targets: list[AuditTarget],
                          unaudited: list[dict[str, Any]]) -> None:
        if not unpinned:
            return
        with ThreadPoolExecutor(max_workers=self.cfg.max_workers) as pool:
            results = list(pool.map(lambda item: self._latest_allowed(item[0]), unpinned))
        for (dep, rel), (ver, err) in zip(unpinned, results):
            if ver is None:
                unaudited.append({"package": dep.normalized, "requirement": dep.raw.strip(),
                                  "file": rel, "line": dep.line, "reason": err})
            else:
                targets.append(AuditTarget(dep.normalized, ver, rel, dep.line or 0,
                                           dep.raw.strip(), "latest-allowed"))

    # ----- pip-audit ------------------------------------------------------- #

    @staticmethod
    def _pip_audit_cmd() -> list[str] | None:
        # Prefer the current interpreter so it works inside the uv venv on Windows/Linux.
        if importlib.util.find_spec("pip_audit"):
            return [sys.executable, "-m", "pip_audit"]
        exe = shutil.which("pip-audit")
        return [exe] if exe else None

    def _run_pip_audit(self, pins: list[tuple[str, str]], tmpdir: Path
                       ) -> tuple[ToolRun, dict[tuple[str, str], list[dict]], dict[tuple[str, str], str]]:
        """Returns (run, {(name, version): raw vulns}, {(name, version): skip reason})."""
        run = ToolRun(tool="pip-audit")
        results: dict[tuple[str, str], list[dict]] = {}
        skipped: dict[tuple[str, str], str] = {}
        base = self._pip_audit_cmd()
        if not base:
            run.status, run.errors = "skipped", ["pip-audit is not installed (pip install pip-audit)"]
            return run, results, skipped
        self.version = run.version = _tool_version([*base, "--version"])
        if not pins:
            return run, results, skipped

        t0 = time.perf_counter()
        for i, batch in enumerate(_batches(pins)):
            req = tmpdir / f"pins-{i}.txt"
            req.write_text("".join(f"{n}=={v}\n" for n, v in batch), encoding="utf-8")
            cmd = [*base, "-r", str(req), "--no-deps", "--disable-pip", "-f", "json",
                   "--progress-spinner", "off", "-s", self.cfg.service, "--desc", "on",
                   "--aliases", "on", "--timeout", str(int(self.cfg.request_timeout))]
            for vid in self.cfg.ignore_vulns:
                cmd += ["--ignore-vuln", vid]
            try:
                proc = _run(cmd, self.cfg.timeout_seconds)
            except subprocess.TimeoutExpired:
                run.status, run.errors = "error", [f"pip-audit timed out after {self.cfg.timeout_seconds}s"]
                return run, {}, {}
            except OSError as exc:
                run.status, run.errors = "error", [f"could not start pip-audit: {exc}"]
                return run, {}, {}

            # Exit code is 1 both for "vulnerabilities found" and for failures: trust the JSON.
            data = _parse_json_stdout(proc.stdout)
            if not isinstance(data, dict) or not isinstance(data.get("dependencies"), list):
                noise = ("--no-deps is supported", "Consider using a tool like")
                err = "\n".join(l for l in (proc.stderr or proc.stdout or "").splitlines()
                                if not any(n in l for n in noise)).strip()
                run.status = "error"
                run.errors.append((err or f"exit code {proc.returncode}")[-800:])
                return run, {}, {}
            for d in data["dependencies"]:
                key = (normalize_name(str(d.get("name") or "")), _canon(str(d.get("version") or "")))
                if d.get("skip_reason"):
                    skipped[key] = str(d["skip_reason"])
                else:
                    results[key] = list(d.get("vulns") or [])
        run.duration_seconds = round(time.perf_counter() - t0, 2)

        # Every pin we sent must come back; a silently dropped package is not "clean".
        for key in pins:
            if key not in results and key not in skipped:
                skipped[key] = "not reported back by pip-audit"
        run.files_scanned = len(pins)
        run.findings = sum(1 for v in results.values() if v)
        return run, results, skipped

    # ----- advisory severity (OSV / GHSA) --------------------------------- #

    def _advisory(self, vuln_id: str) -> tuple[str, list[str]] | None:
        try:
            resp = self.session.get(OSV_VULN_URL.format(id=vuln_id), timeout=self.cfg.request_timeout)
            if resp.status_code != 200:
                return None
            spec = resp.json().get("database_specific") or {}
        except (requests.RequestException, ValueError):
            return None
        sev = str(spec.get("severity") or "UNKNOWN").upper()
        return (sev if sev in _ADVISORY_RANK else "UNKNOWN"), [str(c) for c in spec.get("cwe_ids") or []]

    def _enrich(self, vulns: list[Vulnerability], run: ToolRun) -> None:
        if not (self.cfg.enrich_severity and vulns):
            return
        # PYSEC records carry no rating; the GHSA alias of the same advisory does.
        lookup = {v.id: next((a for a in [v.id, *v.aliases] if a.startswith("GHSA-")), v.id) for v in vulns}
        ids = sorted(set(lookup.values()))
        with ThreadPoolExecutor(max_workers=self.cfg.max_workers) as pool:
            info = dict(zip(ids, pool.map(self._advisory, ids)))
        failed = 0
        for v in vulns:
            got = info.get(lookup[v.id])
            if got is None:
                failed += 1
                continue
            v.advisory_severity, v.cwe = got
            v.severity = _ADVISORY_SEVERITY.get(v.advisory_severity, "medium")
        if failed:
            run.errors.append(f"[info] severity rating unavailable for {failed} advisory(ies) - "
                              "treated as medium (needs review)")

    # ----- orchestration --------------------------------------------------- #

    def scan(self, target: str | Path) -> dict[str, Any]:
        target = Path(target).resolve()
        if not target.exists():
            raise FileNotFoundError(target)
        root = target if target.is_dir() else target.parent
        manifests = find_manifests(root, self.cfg.excluded_dirs) if target.is_dir() else [target]

        targets, unpinned, unaudited = self._collect(root, manifests)
        self._resolve_unpinned(unpinned, targets, unaudited)

        by_key: dict[tuple[str, str], list[AuditTarget]] = defaultdict(list)
        for t in targets:
            by_key[(t.package, t.version)].append(t)
        pins = sorted(by_key)

        with tempfile.TemporaryDirectory(prefix="shipsafe-pip-audit-") as td:
            run, results, skipped = self._run_pip_audit(pins, Path(td))
        if run.status != "ok" and pins:
            unaudited.extend({"package": t.package, "requirement": t.requirement, "file": t.file,
                              "line": t.line, "reason": f"pip-audit {run.status}"}
                             for key in pins for t in by_key[key][:1])
        for key, reason in skipped.items():
            for t in by_key.get(key, [])[:1]:
                unaudited.append({"package": t.package, "requirement": t.requirement, "file": t.file,
                                  "line": t.line, "reason": f"skipped by pip-audit: {reason}"})

        findings = self._findings(root, results, by_key, run)
        stats = {
            "packages_audited": len(results),
            "unpinned_resolved": sum(1 for t in targets if t.resolved_from == "latest-allowed"),
            "from_lockfile": sum(1 for t in targets if t.resolved_from == "lockfile"),
        }
        return build_report(str(target), [_rel(str(m), root) for m in manifests], [run],
                            findings, unaudited, stats, self)

    # ----- findings -------------------------------------------------------- #

    def _findings(self, root: Path, results: dict[tuple[str, str], list[dict]],
                  by_key: dict[tuple[str, str], list[AuditTarget]], run: ToolRun
                  ) -> list[VulnerableDependencyFinding]:
        per_key: dict[tuple[str, str], list[Vulnerability]] = {}
        for key, raw in results.items():
            merged: dict[str, Vulnerability] = {}
            for r in raw:                      # OSV returns the same id more than once
                vid = str(r.get("id") or "")
                if not vid:
                    continue
                v = merged.setdefault(vid, Vulnerability(id=vid, url=OSV_PAGE_URL.format(id=vid)))
                v.aliases = sorted(set(v.aliases) | {str(a) for a in r.get("aliases") or []})
                v.fix_versions = sorted(set(v.fix_versions) | {str(f) for f in r.get("fix_versions") or []},
                                        key=lambda s: _version(s) or Version("0"))
                desc = " ".join(str(r.get("description") or "").split())
                if desc and (not v.summary or len(desc) < len(v.summary)):
                    v.summary = desc[:300]     # shortest description is the title-like one
            if merged:
                per_key[key] = list(merged.values())

        self._enrich([v for vs in per_key.values() for v in vs], run)
        findings = [self._make_finding(root, key, vulns, by_key[key]) for key, vulns in per_key.items()]
        findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line, f.package))
        return findings

    def _make_finding(self, root: Path, key: tuple[str, str], vulns: list[Vulnerability],
                      sources: list[AuditTarget]) -> VulnerableDependencyFinding:
        pkg, ver = key
        sources = sorted(sources, key=lambda t: (not t.direct, _RESOLVED_RANK[t.resolved_from], t.file))
        primary = sources[0]
        vulns.sort(key=lambda v: (-_ADVISORY_RANK[v.advisory_severity], v.id))
        severity = max((v.severity for v in vulns), key=SEVERITY_ORDER.__getitem__)

        current = _version(ver)
        fixes, unfixed = [], []
        for v in vulns:
            newer = [x for x in map(_version, v.fix_versions) if x and (current is None or x > current)]
            (fixes.append(min(newer)) if newer else unfixed.append(v.display_id))
        fix_version = str(max(fixes)) if fixes else None

        n = len(vulns)
        ids = ", ".join(v.display_id for v in vulns[:6]) + (f" (+{n - 6} more)" if n > 6 else "")
        cwe = sorted({c for v in vulns for c in v.cwe}) or ["CWE-1395"]

        f = VulnerableDependencyFinding(
            id=hashlib.sha256(f"pip-audit|{pkg}|{ver}".encode()).hexdigest()[:10],
            tool="pip-audit",
            rule_id="vulnerable-dependency",
            title=f"{pkg} {ver}: {n} known vulnerabilit{'y' if n == 1 else 'ies'}",
            message=f"{pkg}=={ver} is affected by {ids}.",
            severity=severity,
            scanner_severity=vulns[0].advisory_severity,
            confidence="MEDIUM" if primary.resolved_from == "latest-allowed" else "HIGH",
            file=primary.file, line=primary.line, end_line=primary.line,
            category="vulnerable-dependency",
            cwe=cwe,
            references=[v.url for v in vulns[:10]],
            context=_snippet(root, primary.file, primary.line, primary.line, self.cfg) if primary.line else "",
            package=pkg,
            installed_version=ver,
            resolved_from=primary.resolved_from,
            direct=any(t.direct for t in sources),
            required_by=primary.required_by,
            requirement=primary.requirement,
            manifests=sorted({f"{t.file}:{t.line}" for t in sources}),
            vulnerabilities=vulns,
            fix_version=fix_version,
            unfixed=unfixed,
        )
        self._explain(f)
        return f

    @staticmethod
    def _explain(f: VulnerableDependencyFinding) -> None:
        """Deterministic reasons + remediation text for the PR report and the LLM."""
        reasons = []
        for level, label in (("critical", "CRITICAL/HIGH"), ("medium", "MODERATE or unrated"),
                             ("info", "LOW")):
            hit = [v.display_id for v in f.vulnerabilities if v.severity == level]
            if hit:
                reasons.append(f"{len(hit)} {label} advisor{'y' if len(hit) == 1 else 'ies'}: "
                               + ", ".join(hit[:4]) + (" ..." if len(hit) > 4 else ""))
        if f.resolved_from == "latest-allowed":
            reasons.append(f"not pinned: {f.installed_version} is the newest release '{f.requirement}' "
                           "allows, so a fresh install gets this version")
        elif not f.direct:
            via = ", ".join(f.required_by[:3]) or "another dependency"
            reasons.append(f"transitive dependency (pulled in by {via}), version from the lockfile")
        f.severity_reasons = reasons

        if f.fix_version:
            fix = f"Upgrade {f.package} to >= {f.fix_version}"
            if f.resolved_from == "latest-allowed":
                fix += f" - the specifier '{f.requirement}' still allows a vulnerable version; tighten it"
            elif not f.direct:
                fix += (" by upgrading the package that requires it, or add an explicit constraint "
                        f"'{f.package}>={f.fix_version}', then re-lock (uv lock --upgrade-package {f.package})")
            fix += "."
            if f.unfixed:
                fix += f" No fixed release yet for {', '.join(f.unfixed)}: check the advisory for a workaround."
        else:
            fix = (f"No fixed release of {f.package} is published for these advisories. Check them for a "
                   "workaround, consider an alternative package, or record a reviewed exception "
                   "(--ignore-vuln ID).")
        f.remediation = fix


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def build_report(target: str, manifests: list[str], runs: list[ToolRun],
                 findings: list[VulnerableDependencyFinding], unaudited: list[dict[str, Any]],
                 stats: dict[str, int], scanner: PipAuditScanner) -> dict[str, Any]:
    counts = {k: 0 for k in ("critical", "medium", "info")}
    for f in findings:
        counts[f.severity] += 1
    tool_failed = any(r.status != "ok" for r in runs)

    if counts["critical"]:
        overall = "critical"
    elif counts["medium"] or tool_failed or unaudited:
        overall = "medium"   # fail-safe: an unaudited dependency needs review, not a pass
    else:
        overall = "good"

    return {
        "tool": "shipsafe-pip-audit-scanner",
        "target": target,
        "manifests": manifests,
        "pip_audit_version": scanner.version,
        "service": scanner.cfg.service,
        "ignored_vulns": list(scanner.cfg.ignore_vulns),
        "overall": overall,
        "counts": counts,
        **stats,
        "vulnerable_packages": len(findings),
        "vulnerabilities": sum(len(f.vulnerabilities) for f in findings),
        "unaudited": unaudited,
        "tools": [asdict(r) for r in runs],
        "findings": [f.to_dict() for f in findings],
    }


def audit_dependencies(target: str | Path, **config: Any) -> dict[str, Any]:
    """Convenience entry point for the LangGraph node / FastAPI backend."""
    return PipAuditScanner(PipAuditConfig(**config)).scan(target)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

_ICON = {"critical": "[CRITICAL]", "medium": "[MEDIUM]  ", "info": "[INFO]    "}


def format_text(report: dict[str, Any]) -> str:
    out = [f"ShipSafe dependency vulnerability scan (pip-audit {report['pip_audit_version'] or '?'}, "
           f"{report['service']}) - overall: {report['overall'].upper()}",
           f"Target: {report['target']}",
           f"Manifests: {', '.join(report['manifests']) or '(none found)'}",
           f"Audited {report['packages_audited']} package versions "
           f"({report['from_lockfile']} from lockfiles, {report['unpinned_resolved']} unpinned -> newest allowed); "
           f"vulnerable packages: {report['vulnerable_packages']}   counts: {report['counts']}"]
    if report["ignored_vulns"]:
        out.append(f"Ignored (reviewed exceptions): {', '.join(report['ignored_vulns'])}")
    out.append("")
    for t in report["tools"]:
        line = f"  {t['tool']:<10} {t['status']:<8} vulnerable={t['findings']}"
        if t["duration_seconds"] is not None:
            line += f"  {t['duration_seconds']}s"
        out.append(line)
        for e in t["errors"][:5]:
            out.append(f"           ! {e}")
    out.append("")
    for f in report["findings"]:
        out.append(f"{_ICON[f['severity']]} {f['file']}:{f['line']}  {f['title']}")
        for v in f["vulnerabilities"][:8]:
            alias = next((a for a in v["aliases"] if a.startswith("CVE-")), v["id"])
            fixed = ", ".join(v["fix_versions"]) or "no fix"
            out.append(f"           {alias:<18} {v['advisory_severity']:<9} fixed in: {fixed:<12} {v['summary'][:70]}")
        if len(f["vulnerabilities"]) > 8:
            out.append(f"           ... {len(f['vulnerabilities']) - 8} more")
        out.append(f"           why: {'; '.join(f['severity_reasons'])}")
        out.append(f"           fix: {f['remediation']}")
    if report["unaudited"]:
        out.append("")
        out.append("Not audited (needs review - NOT the same as clean):")
        for u in report["unaudited"]:
            loc = f"{u['file']}:{u['line']}" if u.get("line") else u["file"]
            out.append(f"  - {u.get('requirement') or '(manifest)'}  [{loc}]  {u['reason']}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ShipSafe known-vulnerability scanner (pip-audit)")
    parser.add_argument("target", help="repository directory, requirements*.txt, pyproject.toml or uv.lock")
    parser.add_argument("--json", action="store_true", help="print the full JSON report")
    parser.add_argument("--service", choices=SERVICES, default="osv", help="advisory database (default: osv)")
    parser.add_argument("--no-lockfiles", action="store_true", help="ignore uv.lock files")
    parser.add_argument("--no-resolve", action="store_true",
                        help="do not look up the newest allowed version for unpinned requirements")
    parser.add_argument("--no-severity", action="store_true", help="skip OSV severity lookup (offline)")
    parser.add_argument("--ignore-vuln", action="append", default=[], metavar="ID",
                        help="reviewed exception, may be repeated")
    args = parser.parse_args(argv)

    cfg = PipAuditConfig(service=args.service, use_lockfiles=not args.no_lockfiles,
                         resolve_unpinned=not args.no_resolve, enrich_severity=not args.no_severity,
                         ignore_vulns=args.ignore_vuln)
    report = PipAuditScanner(cfg).scan(args.target)
    print(json.dumps(report, indent=2) if args.json else format_text(report))
    return {"good": 0, "medium": 2, "critical": 1}[report["overall"]]


if __name__ == "__main__":
    sys.exit(main())
