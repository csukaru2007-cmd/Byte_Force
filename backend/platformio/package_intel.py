"""Component A - PlatformIO package intelligence.

For each dependency extracted from the project this module
  1. retrieves the registry metadata that actually exists (never invents fields),
  2. compares the package identity with databases/trusted_packages.json,
  3. produces findings (PKG001-PKG011) with evidence.

A finding is an indicator for review. Nothing here classifies a package as malicious.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from backend.config import DATABASES
from backend.models import Finding, ScanIssue
from backend.platformio.ini_parser import Dependency, DependencyExtraction
from backend.platformio.registry_client import RegistryClient, RegistryError, RegistryResult
from backend.platformio.similarity import best_match
from backend.security_engine.rule_loader import package_rules

COMPONENT = "platformio_intelligence"
_EXACT_VERSION = re.compile(r"^\d+(\.\d+){0,3}([-+][\w.]+)?$")


@lru_cache(maxsize=1)
def _trusted_db() -> tuple[dict, ...]:
    data = json.loads((DATABASES / "trusted_packages.json").read_text(encoding="utf-8"))
    return tuple(data["packages"])


def load_trusted_packages() -> list[dict]:
    return list(_trusted_db())


def verified_owners(entry: dict) -> set[str]:
    owners = {entry["registry_owner"].lower()}
    owners.update(p["registry_owner"].lower() for p in entry.get("additional_verified_publishers", []))
    return owners


def _repo_key(url: str | None) -> str | None:
    if not url:
        return None
    url = url.strip().lower().removeprefix("git+")
    url = re.sub(r"^(https?://|ssh://|git@)", "", url).replace("github.com:", "github.com/")
    url = url.split("#")[0].removesuffix("/").removesuffix(".git")
    return url


def verified_repositories(entry: dict) -> set[str]:
    repos = {_repo_key(entry["repository"])}
    repos.update(_repo_key(p["repository"]) for p in entry.get("additional_verified_publishers", []))
    return repos


def normalise_metadata(result: RegistryResult, dlstats: dict | None) -> dict:
    """Keep the registry fields we use; absent fields stay None."""
    data = result.data
    owner = data.get("owner") or {}
    version = data.get("version") or {}
    versions = [v.get("name") for v in data.get("versions") or [] if isinstance(v, dict)]
    metadata = {
        "registry_id": data.get("id"),
        "name": data.get("name"),
        "type": data.get("type"),
        "owner": owner.get("username"),
        "owner_is_organisation": owner.get("is_org"),
        "description": data.get("description"),
        "latest_version": version.get("name"),
        "latest_release_date": version.get("released_at"),
        "versions_count": len(versions) if data.get("versions") is not None else None,
        "versions": versions[-30:] if versions else None,
        "first_published": data.get("added_at"),
        "last_updated": data.get("updated_at") or data.get("modified_at"),
        "repository_url": data.get("repository_url"),
        "homepage": data.get("homepage"),
        "license": data.get("license"),
        "keywords": data.get("keywords"),
        "frameworks": data.get("frameworks"),
        "platforms": data.get("platforms"),
        "popularity_rank": data.get("popularity_rank"),
        "stars_count": data.get("stars_count"),
        "dependents_count": data.get("dependents_count"),
        "tier": data.get("tier"),
        "downloads": None,
        "source_url": result.url,
        "retrieved_at": result.retrieved_at,
        "from_cache": result.from_cache,
        "stale_cache": result.stale,
    }
    if dlstats:
        daily: dict[str, int] = {}
        for entry in dlstats.get("versions", []):
            for day, count in (entry.get("daily") or {}).items():
                if isinstance(count, int):
                    daily[day] = daily.get(day, 0) + count
        if daily:
            metadata["downloads"] = {"total_in_window": sum(daily.values()),
                                     "window_start": min(daily), "window_end": max(daily),
                                     "note": "Sum of the daily counts returned by the registry dlstats endpoint."}
    return metadata


def _ini_line(root: Path | None, raw: str) -> int | None:
    if root is None:
        return None
    try:
        for number, line in enumerate((root / "platformio.ini").read_text(encoding="utf-8").splitlines(), 1):
            if raw in line:
                return number
    except OSError:
        return None
    return None


class PackageAnalyser:
    def __init__(self, client: RegistryClient, project_root: Path | None = None,
                 fetch_download_stats: bool = True):
        self.client = client
        self.root = project_root
        self.rules = package_rules()
        self.trusted = load_trusted_packages()
        self.fetch_download_stats = fetch_download_stats
        self.issues: list[ScanIssue] = []
        self._reported_registry_failure = False

    # -------------------------------------------------------------- helpers
    def _location(self, dep: Dependency) -> tuple[str, int | None]:
        if dep.field == "lib_dir":
            return dep.url or f"lib/{dep.name}", None
        if dep.field == "installed":
            return (dep.installed or {}).get("path", ".pio/libdeps"), None
        return "platformio.ini", _ini_line(self.root, dep.raw)

    def _finding(self, rule_id: str, dep: Dependency, evidence: str, **kwargs) -> Finding:
        file, line = self._location(dep)
        kwargs.setdefault("details", {})["package"] = dep.display_name
        return self.rules[rule_id].finding(COMPONENT, file=file, line=line, evidence=evidence,
                                           origin="platformio.ini", **kwargs)

    def _registry_failed(self, dep: Dependency, error: RegistryError, result: dict) -> None:
        result["metadata_status"] = "unavailable"
        result["metadata_error"] = f"{error.reason}: {error}"
        result["findings"].append(self._finding(
            "PKG008", dep, f"{dep.display_name}: {error.reason} ({error})"))
        if not self._reported_registry_failure:
            self._reported_registry_failure = True
            self.issues.append(ScanIssue("registry", f"PlatformIO Registry unavailable ({error.reason}): {error}. "
                                         "Metadata checks are incomplete; cached answers were used where available.",
                                         level="WARNING"))

    # -------------------------------------------------------------- main
    def analyse(self, extraction: DependencyExtraction) -> list[dict]:
        return [self.analyse_dependency(dep) for dep in extraction.dependencies]

    def analyse_dependency(self, dep: Dependency) -> dict:
        result: dict = {
            "component": COMPONENT,
            "package": dep.display_name,
            "kind": dep.kind,
            "dependency": dep.to_dict(),
            "metadata_status": "not_applicable",
            "metadata": None,
            "registry_candidates": None,
            "trust_status": "not_applicable",
            "matched_trusted_package": None,
            "similarity": None,
            "findings": [],
        }
        if dep.kind in ("framework_builtin", "framework"):
            result["trust_status"] = "framework_component"
        elif dep.kind == "local":
            result["trust_status"] = "local_source"
            if dep.field == "lib_deps":
                result["findings"].append(self._finding("PKG011", dep, dep.raw, confidence="DEFINITE"))
        elif dep.source in ("git", "archive"):
            self._analyse_url_dependency(dep, result)
        elif dep.kind == "registry_legacy_id":
            result["metadata_status"] = "unresolved"
            result["findings"].append(self._finding(
                "PKG008", dep, f"legacy numeric registry ID {dep.name} is not resolved by ShipSafe",
                description="Legacy numeric registry ID was not resolved; identity checks were skipped."))
        elif dep.kind in ("platform", "tool_package"):
            self._analyse_registry_package(dep, result, check_identity=False)
        else:
            self._analyse_registry_package(dep, result, check_identity=True)
        result["findings"] = [f.to_dict() for f in result["findings"]]
        return result

    # -------------------------------------------------------------- URL dependencies
    def _analyse_url_dependency(self, dep: Dependency, result: dict) -> None:
        result["metadata_status"] = "not_in_registry"
        result["trust_status"] = "url_source"
        pinned = dep.git_pin in ("commit", "tag")
        severity = "INFO" if pinned else "LOW"
        pin_text = f"pinned to {dep.git_pin} '{dep.git_ref}'" if pinned else (
            f"ref '{dep.git_ref}' may be a moving branch" if dep.git_ref else "no commit or tag")
        result["findings"].append(self._finding("PKG009", dep, f"{dep.url} ({pin_text})", severity=severity))

        name = dep.custom_name or dep.repo_name or dep.name
        match = best_match(name, self.trusted) if dep.field == "lib_deps" else None
        if not match:
            return
        result["matched_trusted_package"] = match.trusted_name
        result["similarity"] = match.to_dict()
        repo = _repo_key(dep.url)
        if repo in verified_repositories(match.trusted_entry):
            result["trust_status"] = "verified_upstream_repository"
            return
        result["trust_status"] = "unverified_repository"
        if match.relation == "exact":
            result["findings"].append(self._finding(
                "PKG006", dep,
                f"'{name}' is fetched from {dep.url}; verified upstream is {match.trusted_entry['repository']}",
                details={"matched_trusted_package": match.trusted_name}))
        else:
            result["findings"].append(self._lookalike_finding(dep, match, owner=dep.repo_owner))

    # -------------------------------------------------------------- registry packages
    def _analyse_registry_package(self, dep: Dependency, result: dict, check_identity: bool) -> None:
        pkg_type = dep.registry_type or "library"
        owner = dep.owner
        metadata_result: RegistryResult | None = None
        try:
            if owner:
                metadata_result = self.client.get_package(owner, pkg_type, dep.name)
            else:
                search = self.client.find_by_name(dep.name, pkg_type)
                candidates = [{"owner": i["owner"]["username"], "name": i["name"],
                               "popularity_rank": i.get("popularity_rank")} for i in search.data or []]
                result["registry_candidates"] = candidates
                if candidates:
                    owner = candidates[0]["owner"]
                    if check_identity:
                        result["findings"].append(self._ambiguity_finding(dep, candidates))
                    metadata_result = self.client.get_package(owner, pkg_type, candidates[0]["name"])
                else:
                    metadata_result = None
        except RegistryError as error:
            self._registry_failed(dep, error, result)
            if check_identity:
                self._identity_checks(dep, owner, None, result)
            return

        if metadata_result is None or not metadata_result.found:
            result["metadata_status"] = "not_found"
            if check_identity:
                where = f"{owner}/{dep.name}" if dep.owner else f"any library named '{dep.name}'"
                result["findings"].append(self._finding("PKG003", dep, f"registry has no {where}"))
                self._identity_checks(dep, owner, None, result, package_exists=False)
            return

        dlstats = None
        if self.fetch_download_stats and pkg_type == "library":
            try:
                stats = self.client.get_dlstats(owner, pkg_type, metadata_result.data["name"])
                dlstats = stats.data if stats.found else None
            except RegistryError:
                dlstats = None
        metadata = normalise_metadata(metadata_result, dlstats)
        result["metadata"] = metadata
        result["metadata_status"] = "stale_cache" if metadata_result.stale else "retrieved"

        missing = [name for name in ("repository_url", "description") if not metadata.get(name)]
        if missing and check_identity:
            result["findings"].append(self._finding(
                "PKG007", dep, f"{dep.display_name}: registry provides no {', '.join(missing)}",
                details={"missing_fields": missing}))

        if dep.version_spec and _EXACT_VERSION.match(dep.version_spec) and metadata.get("versions") is not None:
            all_versions = [v.get("name") for v in metadata_result.data.get("versions") or []]
            if dep.version_spec not in all_versions:
                result["findings"].append(self._finding(
                    "PKG005", dep,
                    f"{dep.display_name}@{dep.version_spec} not published; latest is {metadata.get('latest_version')}"))

        if check_identity:
            self._identity_checks(dep, metadata.get("owner") or owner, metadata, result)

    def _ambiguity_finding(self, dep: Dependency, candidates: list[dict]) -> Finding:
        owners = sorted({c["owner"] for c in candidates})
        severity = "MEDIUM" if len(owners) > 1 else "LOW"
        return self._finding("PKG004", dep, f"'{dep.name}' is published by: {', '.join(owners)}",
                             severity=severity, details={"owners": owners})

    def _lookalike_finding(self, dep: Dependency, match, owner: str | None) -> Finding:
        # Calibrated on 1,152 real registry names (docs/similarity_calibration.json):
        # word-level relations mostly hit legitimate extension libraries, so they are weaker evidence.
        severity = {"confusable": "HIGH", "edit": "MEDIUM"}.get(match.relation, "LOW")
        return self._finding(
            "PKG001", dep,
            f"'{match.candidate}' resembles trusted '{match.matched_alias}' "
            f"({match.relation}: {match.difference}; similarity {match.similarity_score})",
            severity=severity,
            description=f"Package name closely resembles the trusted package '{match.trusted_name}'.",
            details={"matched_trusted_package": match.trusted_name, "similarity": match.to_dict(),
                     "publisher": owner, "verified_publishers": sorted(verified_owners(match.trusted_entry))})

    def _identity_checks(self, dep: Dependency, owner: str | None, metadata: dict | None, result: dict,
                         package_exists: bool = True) -> None:
        name = (metadata or {}).get("name") or dep.name
        match = best_match(name, self.trusted)
        if match is None:
            result["trust_status"] = "not_in_trusted_database"
            return
        result["matched_trusted_package"] = match.trusted_name
        result["similarity"] = match.to_dict()
        owners = verified_owners(match.trusted_entry)
        owner_verified = bool(owner) and owner.lower() in owners

        if match.relation == "exact":
            if owner_verified:
                result["trust_status"] = "verified_trusted"
                repo = _repo_key((metadata or {}).get("repository_url"))
                if metadata and repo and repo not in verified_repositories(match.trusted_entry):
                    result["trust_status"] = "verified_owner_repository_changed"
                    result["findings"].append(self._finding(
                        "PKG006", dep, f"registry repository_url {metadata['repository_url']} "
                                       f"!= verified {match.trusted_entry['repository']}"))
                self._installed_checks(dep, match.trusted_entry, result)
            elif owner is None:
                result["trust_status"] = "unverified_owner_unknown"
            elif package_exists:
                result["trust_status"] = "trusted_name_other_publisher"
                result["findings"].append(self._finding(
                    "PKG002", dep,
                    f"{owner}/{name}: verified publisher is {match.trusted_entry['registry_owner']}",
                    details={"matched_trusted_package": match.trusted_name, "publisher": owner,
                             "verified_publishers": sorted(owners)}))
            else:
                result["trust_status"] = "trusted_name_missing_owner_package"
            return

        if owner_verified:
            # e.g. 'Adafruit BME680 Library' by adafruit vs trusted 'Adafruit BME280 Library':
            # a different, legitimate package from the same verified publisher.
            result["trust_status"] = "similar_name_same_verified_publisher"
            return
        result["trust_status"] = "lookalike_name"
        result["findings"].append(self._lookalike_finding(dep, match, owner))

    def _installed_checks(self, dep: Dependency, entry: dict, result: dict) -> None:
        installed = dep.installed
        if not installed:
            return
        problems = []
        if installed.get("owner") and dep.owner and installed["owner"].lower() != dep.owner.lower():
            problems.append(f"installed owner {installed['owner']} != declared {dep.owner}")
        valid_ids = {entry.get("registry_id")} | {p.get("registry_id") for p in entry.get("additional_verified_publishers", [])}
        if installed.get("registry_id") and entry.get("registry_id") and installed["registry_id"] not in valid_ids:
            problems.append(f"installed registry id {installed['registry_id']} != trusted id {entry['registry_id']}")
        if problems:
            result["findings"].append(self._finding("PKG010", dep, "; ".join(problems),
                                                    details={"installed": installed}))


def analyse_packages(extraction: DependencyExtraction, client: RegistryClient,
                     project_root: Path | None = None) -> tuple[list[dict], list[ScanIssue]]:
    analyser = PackageAnalyser(client, project_root)
    results = analyser.analyse(extraction)
    return results, analyser.issues
