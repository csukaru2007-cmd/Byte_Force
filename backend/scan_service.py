"""Scan orchestration: upload -> extraction -> three components -> unified report.

Stages: extracting, dependencies, registry, parsing, hardware, security, risk, completed.
Every stage is guarded: a failure is recorded in `errors` and the remaining stages
still run, so one unavailable service never hides the other results.
"""

from __future__ import annotations

import json
import threading
import time
import traceback
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from backend import config
from backend.ast_engine.clang_parser import clang_status
from backend.ast_engine.runner import ASTAnalysis, analyse_sources
from backend.ast_engine.ast_extractor import ProjectFeatures
from backend.hardware.checker import HardwareResult, check_hardware
from backend.hardware.profiles import list_profiles
from backend.models import Finding, ScanIssue, dedupe_findings, severity_rank
from backend.platformio.ini_parser import extract_dependencies
from backend.platformio.package_intel import analyse_packages, load_trusted_packages
from backend.platformio.registry_client import RegistryClient
from backend.project_loader import (ProjectError, cleanup, locate_project_root, safe_extract,
                                    validate_project)
from backend.risk_engine import assess_risk
from backend.baseline_client import baseline_status, run_baseline
from backend.decision import final_decision, main_engine_decision
from backend.ml.predict import ml_status, predict_project
from backend.security_engine.engine import run_security_engine
from backend.security_engine.rule_loader import hardware_rules, package_rules, security_rules

VERSION = "2.0.0"
STAGES = ["extracting", "dependencies", "registry", "parsing", "hardware", "security", "risk", "ml", "baseline",
          "completed"]
DISCLAIMER = ("ShipSafe reports observable indicators with evidence. A finding is not proof of malicious intent, "
              "and the absence of findings is not proof of safety.")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScanRecord:
    scan_id: str
    status: str = "queued"            # queued | running | completed | failed
    stage: str = "queued"
    created_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    result: dict | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        data: dict[str, Any] = {"scan_id": self.scan_id, "status": self.status, "stage": self.stage,
                                "stages": STAGES, "created_at": self.created_at,
                                "finished_at": self.finished_at}
        if self.error:
            data["error"] = self.error
        if self.result is not None:
            data.update(self.result)
        return data


class ScanStore:
    """In-memory store of recent scans (thread-safe, bounded)."""

    def __init__(self, limit: int | None = None):
        self.limit = limit or config.MAX_STORED_SCANS
        self._scans: OrderedDict[str, ScanRecord] = OrderedDict()
        self._lock = threading.Lock()

    def create(self) -> ScanRecord:
        record = ScanRecord(scan_id=uuid.uuid4().hex[:12])
        with self._lock:
            self._scans[record.scan_id] = record
            while len(self._scans) > self.limit:
                self._scans.popitem(last=False)
        return record

    def get(self, scan_id: str) -> ScanRecord | None:
        with self._lock:
            return self._scans.get(scan_id)


def _guard(stage: str, issues: list[ScanIssue], fn, *args, fallback=None, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as error:  # noqa: BLE001 - keep the scan alive and report the failure
        issues.append(ScanIssue(stage, f"{stage} stage failed: {type(error).__name__}: {error}",
                                details={"traceback": traceback.format_exc(limit=4)}))
        return fallback


def analyse_project(root: Path, *, chip: str | None, project_name: str, work_dir: Path,
                    registry: RegistryClient | None = None,
                    on_stage: Callable[[str], None] = lambda s: None) -> dict:
    """Run every component on an extracted project and build the unified report."""
    deadline = time.monotonic() + config.SCAN_TIME_LIMIT_SECONDS
    issues: list[ScanIssue] = []
    info = validate_project(root, project_name)
    issues += [ScanIssue("upload", w, level="WARNING") for w in info.warnings]

    # Component A ---------------------------------------------------------------
    on_stage("dependencies")
    extraction = extract_dependencies(root)
    on_stage("registry")
    registry = registry or RegistryClient()
    package_results, package_issues = _guard("registry", issues, analyse_packages, extraction, registry, root,
                                             fallback=([], []))
    issues += package_issues
    package_findings = [Finding(**f) for r in package_results for f in r["findings"]]

    # Clang AST (shared by components B and C) -----------------------------------
    on_stage("parsing")
    env = next((e for e in extraction.environments if e.name in extraction.default_envs), None) or \
        (extraction.environments[0] if extraction.environments else None)
    ast: ASTAnalysis = _guard("parser", issues, analyse_sources, root, env, work_dir / "ast", deadline,
                              fallback=ASTAnalysis(ProjectFeatures(), None, available=False))
    issues += ast.issues

    # Component B ---------------------------------------------------------------
    on_stage("hardware")
    hardware: HardwareResult = _guard("hardware", issues, check_hardware, ast.features, chip,
                                      extraction.environments, fallback=HardwareResult(status="skipped"))
    issues += hardware.issues

    # Component C ---------------------------------------------------------------
    on_stage("security")
    security_findings, security_issues, security_summary = _guard(
        "security", issues, run_security_engine, ast.features, root, package_results, fallback=([], [], {}))
    issues += security_issues

    # Unified findings + risk ------------------------------------------------------
    on_stage("risk")
    all_findings = dedupe_findings(package_findings + hardware.findings + security_findings)
    all_findings.sort(key=lambda f: (-severity_rank(f.severity), f.component, f.file or "", f.line or 0))
    registry_ok = not any(r["metadata_status"] == "unavailable" for r in package_results)
    risk = assess_risk(all_findings, issues, hardware_status=hardware.status, registry_available=registry_ok,
                       files_parsed=len(ast.parse_results))
    finding_dicts = [f.to_dict() for f in all_findings]
    main_decision = main_engine_decision(finding_dicts, risk, completed=True)
    on_stage("ml")
    ml = _guard("ml", issues, predict_project, root, package_results,
                fallback={"status": "unavailable", "label": None, "reason": "ML stage crashed"})

    parser_errors = sum(r.error_count for r in ast.parse_results)
    return {
        "project": {
            "name": info.name,
            "chip": (hardware.profile or {}).get("module") or chip,
            "chip_selection": hardware.selection,
            "environments": [e.to_dict() for e in extraction.environments],
            "default_envs": extraction.default_envs,
            "analysed_environment": env.name if env else None,
            **info.to_dict(),
        },
        "summary": {
            "dependencies_scanned": len(package_results),
            "package_findings": len(package_findings),
            "hardware_findings": len(hardware.findings),
            "security_findings": len(security_findings),
            "total_findings": len(all_findings),
            "files_parsed": len(ast.parse_results),
            "parser_errors": parser_errors,
            "issues": len(issues),
        },
        "package_results": package_results,
        "hardware_results": [f.to_dict() for f in hardware.findings],
        "hardware_analysis": {k: v for k, v in hardware.to_dict().items() if k != "findings"},
        "security_results": [f.to_dict() for f in security_findings],
        "security_analysis": security_summary,
        "findings": finding_dicts,
        "main_engine_decision": main_decision,
        "ml_prediction": ml,
        "decision": final_decision(main_decision, ml),
        "errors": [i.to_dict() for i in issues],
        "risk_assessment": risk,
        "analysis": {
            "dependency_notes": extraction.notes,
            "ast": ast.summary(root) if ast.context else {"clang": clang_status(), "files_parsed": 0},
            "registry": {"network_calls": registry.network_calls, "disabled_reason": registry.disabled_reason},
        },
        "disclaimer": DISCLAIMER,
    }


def available_profiles() -> dict:
    return {"profiles": list_profiles(), "default": "auto"}


def health_info() -> dict:
    status = {"status": "ok", "version": VERSION, "clang": clang_status(), "ml": ml_status(),
              "baseline": baseline_status()}
    try:
        status["rules"] = {"package": len(package_rules().rules), "hardware": len(hardware_rules().rules),
                           "security": len(security_rules().rules)}
        status["trusted_packages"] = len(load_trusted_packages())
    except Exception as error:  # noqa: BLE001
        status["status"] = "degraded"
        status["error"] = str(error)
    if not status["clang"]["available"]:
        status["status"] = "degraded"
    return status


def run_scan_job(record: ScanRecord, zip_path: Path, work_dir: Path, *, chip: str | None,
                 project_name: str, demo: bool = False, keep_files: bool = False,
                 registry_factory: Callable[[], RegistryClient] | None = None,
                 registry_offline: bool = False, report_dir: Path | None = None,
                 run_baseline_scan: bool = True) -> None:
    """Background job. Always cleans up the work folder (unless keep_files for debugging)."""
    started = time.monotonic()
    record.status, record.stage = "running", "extracting"

    def on_stage(stage: str) -> None:
        record.stage = stage

    try:
        extract_dir = work_dir / "project"
        extract_dir.mkdir()
        extraction = safe_extract(zip_path, extract_dir)
        root = locate_project_root(extract_dir)
        registry = registry_factory() if registry_factory else RegistryClient(offline=registry_offline)
        result = analyse_project(root, chip=chip, project_name=project_name, work_dir=work_dir,
                                 registry=registry, on_stage=on_stage)
        if run_baseline_scan:
            on_stage("baseline")
            try:
                result["baseline"] = run_baseline(zip_path.read_bytes(), f"{project_name}.zip")
            except Exception as error:  # noqa: BLE001 - the baseline must never break the scan
                result["baseline"] = {"status": "unavailable", "reason": f"Baseline crashed: {error}"}
        else:
            result["baseline"] = {"status": "skipped", "reason": "Baseline comparison not requested."}
        if extraction.skipped:
            result["errors"].insert(0, ScanIssue(
                "upload", f"{len(extraction.skipped)} archive entries were not extracted for safety.",
                level="WARNING", details={"skipped": extraction.skipped[:50]}).to_dict())
        result["demo"] = demo
        result["scan_seconds"] = round(time.monotonic() - started, 2)
        result["generated_at"] = utc_now()
        result["shipsafe_version"] = VERSION
        record.result = result
        record.status, record.stage = "completed", "completed"
        if report_dir:
            report_dir.mkdir(parents=True, exist_ok=True)
            (report_dir / f"{record.scan_id}.json").write_text(json.dumps(record.to_dict(), indent=1),
                                                               encoding="utf-8")
    except ProjectError as error:
        record.status, record.error = "failed", str(error)
    except Exception as error:  # noqa: BLE001 - report any crash instead of losing the scan
        record.status, record.error = "failed", f"Internal error: {type(error).__name__}: {error}"
    finally:
        if record.status == "failed":
            main_decision = main_engine_decision([], None, completed=False)
            record.result = {"decision": final_decision(main_decision, {"status": "unavailable",
                                                                        "reason": "scan failed"}),
                             "main_engine_decision": main_decision}
        record.finished_at = utc_now()
        if not keep_files:
            cleanup(work_dir)
