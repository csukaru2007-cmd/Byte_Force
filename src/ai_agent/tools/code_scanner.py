"""ShipSafe code scanner: static analysis with Bandit (Python) + Semgrep (multi-language).

Both tools look for insecure code patterns (injection, unsafe deserialization,
weak crypto, shell=True, debug mode, missing auth checks via custom rules, ...).
Their raw outputs are converted into ONE common finding format so the rest of
the pipeline (dedup -> LLM triage -> policy engine -> PR report) does not need
to know which scanner produced a finding.

    Bandit   - Python only, fast, no network needed.
    Semgrep  - Python, JS/TS, Java, Go, PHP, Ruby, C#, ... (rules from the
               Semgrep registry, plus any local rules in ./semgrep_rules or
               <repo>/.shipsafe/semgrep).

Severity of a single finding (same vocabulary as dependency_checker):
    critical  - high-impact pattern the scanner is confident about
    medium    - real risk or uncertain high-impact pattern -> needs review
    info      - low-impact / hygiene, never blocks on its own

Tool failures are never silently treated as "no findings": each tool reports
status ok | error | skipped, and an error forces the overall result to at
least "medium" (fail-safe, see report section 13).

The LLM never sees raw scanner JSON - it gets the normalized finding plus a
bounded code snippet (`context`) taken directly from the file.

CLI:
    python -m ai_agent.tools.code_scanner <repo_dir_or_file> [--json] [--no-semgrep] [--no-bandit]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

SEVERITY_ORDER = {"good": 0, "info": 1, "medium": 2, "critical": 3}

# Directories that are never application code.
EXCLUDED_DIRS = [
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__", "site-packages",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
]

# Local custom rules (e.g. missing-authorization patterns) are picked up automatically.
_PKG_RULES_DIR = Path(__file__).resolve().parent / "semgrep_rules"
_REPO_RULES_SUBDIR = Path(".shipsafe") / "semgrep"


@dataclass
class ScannerConfig:
    run_bandit: bool = True
    run_semgrep: bool = True
    # Registry rule packs. p/default is multi-language; the others add depth
    # for the threats in the project report (injection, OWASP Top 10).
    semgrep_configs: list[str] = field(default_factory=lambda: [
        "p/default", "p/python", "p/owasp-top-ten",
    ])
    timeout_seconds: int = 600
    context_lines: int = 3            # lines of code before/after a finding for the LLM
    max_snippet_chars: int = 1500
    excluded_dirs: list[str] = field(default_factory=lambda: list(EXCLUDED_DIRS))


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    id: str                    # stable short hash, used to reference findings in LLM output
    tool: str                  # "bandit" | "semgrep" | "bandit+semgrep" after dedup
    rule_id: str               # e.g. "B608" or "python.lang.security.audit.formatted-sql-query..."
    title: str
    message: str
    severity: str              # critical | medium | info  (normalized)
    scanner_severity: str      # raw value from the tool (HIGH / ERROR / ...)
    confidence: str            # HIGH | MEDIUM | LOW | UNKNOWN
    file: str                  # repo-relative, forward slashes
    line: int
    end_line: int
    category: str              # injection | secrets | crypto | deserialization | ... | other
    cwe: list[str] = field(default_factory=list)       # e.g. ["CWE-89"]
    owasp: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    context: str = ""          # numbered code snippet around the finding
    also_reported_by: list[str] = field(default_factory=list)   # duplicate rule ids merged in

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolRun:
    tool: str
    status: str = "ok"         # ok | error | skipped
    version: str | None = None
    findings: int = 0
    files_scanned: int | None = None
    errors: list[str] = field(default_factory=list)
    duration_seconds: float | None = None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _finding_id(tool: str, rule: str, file: str, line: int) -> str:
    return hashlib.sha256(f"{tool}|{rule}|{file}|{line}".encode()).hexdigest()[:10]


def _rel(path: str, root: Path) -> str:
    p = Path(path)
    if not p.is_absolute():
        p = root / p          # scanners are run with cwd=root
    try:
        return p.resolve().relative_to(root).as_posix()
    except ValueError:
        return p.as_posix()


def _snippet(root: Path, rel_file: str, line: int, end_line: int, cfg: ScannerConfig) -> str:
    """Bounded code context read straight from disk (Semgrep OSS no longer returns lines)."""
    path = root / rel_file if not Path(rel_file).is_absolute() else Path(rel_file)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(1, line - cfg.context_lines)
    stop = min(len(lines), max(end_line, line) + cfg.context_lines)
    out = []
    for n in range(start, stop + 1):
        marker = ">" if line <= n <= max(end_line, line) else " "
        out.append(f"{marker}{n:5d} | {lines[n - 1]}")
    text = "\n".join(out)
    return text[: cfg.max_snippet_chars]


def _norm_cwe(values: Any) -> list[str]:
    """Turn 'CWE-89: Improper Neutralization...' / {'id': 89} / 89 into 'CWE-89'."""
    if values is None:
        return []
    if not isinstance(values, list):
        values = [values]
    out = []
    for v in values:
        if isinstance(v, dict):
            v = v.get("id")
        s = str(v).strip()
        if not s:
            continue
        s = s.split(":")[0].strip()
        if not s.upper().startswith("CWE-"):
            s = f"CWE-{s}"
        out.append(s.upper())
    return sorted(set(out))


# CWE -> category, used for grouping in the report and for the LLM prompt.
_CWE_CATEGORY = {
    "CWE-78": "injection", "CWE-77": "injection", "CWE-89": "injection", "CWE-94": "injection",
    "CWE-95": "injection", "CWE-79": "xss", "CWE-1336": "injection", "CWE-643": "injection",
    "CWE-90": "injection", "CWE-611": "xxe", "CWE-502": "deserialization",
    "CWE-798": "secrets", "CWE-259": "secrets", "CWE-321": "secrets",
    "CWE-327": "crypto", "CWE-328": "crypto", "CWE-326": "crypto", "CWE-330": "crypto",
    "CWE-295": "tls", "CWE-319": "tls", "CWE-22": "path-traversal", "CWE-918": "ssrf",
    "CWE-862": "authorization", "CWE-863": "authorization", "CWE-285": "authorization",
    "CWE-639": "authorization", "CWE-306": "authentication", "CWE-287": "authentication",
    "CWE-352": "csrf", "CWE-601": "open-redirect", "CWE-489": "debug", "CWE-215": "debug",
    "CWE-605": "network", "CWE-400": "dos", "CWE-377": "filesystem", "CWE-732": "filesystem",
}


def _category(cwes: list[str], rule_id: str) -> str:
    for c in cwes:
        if c in _CWE_CATEGORY:
            return _CWE_CATEGORY[c]
    r = rule_id.lower()
    for key, cat in (("sql", "injection"), ("inject", "injection"), ("subprocess", "injection"),
                     ("secret", "secrets"), ("password", "secrets"), ("token", "secrets"),
                     ("pickle", "deserialization"), ("yaml", "deserialization"),
                     ("crypto", "crypto"), ("hash", "crypto"), ("auth", "authorization"),
                     ("debug", "debug"), ("ssl", "tls"), ("xss", "xss")):
        if key in r:
            return cat
    return "other"


def _bandit_severity(sev: str, conf: str) -> str:
    sev, conf = sev.upper(), conf.upper()
    if sev == "HIGH":
        return "critical" if conf in ("HIGH", "MEDIUM") else "medium"
    if sev == "MEDIUM":
        return "medium" if conf != "LOW" else "info"
    return "info"


def _semgrep_severity(sev: str, conf: str, impact: str) -> str:
    sev, conf, impact = sev.upper(), conf.upper(), impact.upper()
    if sev in ("ERROR", "CRITICAL", "HIGH"):
        # Registry "audit" rules are ERROR but LOW confidence: worth review, not a block.
        return "critical" if conf in ("HIGH", "MEDIUM", "UNKNOWN") else "medium"
    if sev in ("WARNING", "MEDIUM"):
        return "medium" if conf != "LOW" or impact == "HIGH" else "info"
    return "info"


def _run(cmd: list[str], timeout: int, cwd: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, env=env, cwd=cwd)


def _parse_json_stdout(stdout: str) -> dict | None:
    """Scanners sometimes print warnings before the JSON; find the JSON object."""
    stdout = stdout.strip()
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        start = stdout.find("{")
        if start == -1:
            return None
        try:
            return json.loads(stdout[start:])
        except json.JSONDecodeError:
            return None


# --------------------------------------------------------------------------- #
# Scanner runners
# --------------------------------------------------------------------------- #

class CodeScanner:
    def __init__(self, config: ScannerConfig | None = None):
        self.cfg = config or ScannerConfig()

    # ----- Bandit --------------------------------------------------------- #

    def run_bandit(self, target: Path, root: Path) -> tuple[ToolRun, list[Finding]]:
        run = ToolRun(tool="bandit")
        # Run via the current interpreter so it works inside the uv venv on Windows/Linux.
        cmd = [sys.executable, "-m", "bandit", "-r", str(target), "-f", "json", "-q",
               "-x", ",".join(f"*/{d}/*" for d in self.cfg.excluded_dirs)]
        t0 = time.perf_counter()
        try:
            proc = _run(cmd, self.cfg.timeout_seconds)
        except FileNotFoundError:
            run.status, run.errors = "skipped", ["bandit is not installed"]
            return run, []
        except subprocess.TimeoutExpired:
            run.status, run.errors = "error", [f"bandit timed out after {self.cfg.timeout_seconds}s"]
            return run, []
        run.duration_seconds = round(time.perf_counter() - t0, 2)

        data = _parse_json_stdout(proc.stdout)
        # Bandit exit codes: 0 = no issues, 1 = issues found, anything else = failure.
        if data is None:
            run.status = "error"
            run.errors.append((proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()[:500])
            return run, []

        for err in data.get("errors", []):
            run.errors.append(f"{_rel(err.get('filename', ''), root)}: {err.get('reason', '')}")
        if run.errors:
            # Files Bandit could not parse were NOT scanned -> do not report as clean.
            run.status = "error"
        run.files_scanned = sum(1 for k in data.get("metrics", {}) if k != "_totals") or None
        run.version = _tool_version([sys.executable, "-m", "bandit", "--version"])

        findings = []
        for r in data.get("results", []):
            rel = _rel(r["filename"], root)
            line = int(r.get("line_number") or 0)
            rng = r.get("line_range") or [line]
            end = int(max(rng)) if rng else line
            cwe = _norm_cwe((r.get("issue_cwe") or {}).get("id"))
            rule = r.get("test_id", "B000")
            sev, conf = r.get("issue_severity", "LOW"), r.get("issue_confidence", "LOW")
            findings.append(Finding(
                id=_finding_id("bandit", rule, rel, line),
                tool="bandit",
                rule_id=rule,
                title=f"{rule} {r.get('test_name', '')}".strip(),
                message=r.get("issue_text", ""),
                severity=_bandit_severity(sev, conf),
                scanner_severity=sev,
                confidence=conf,
                file=rel, line=line, end_line=end,
                category=_category(cwe, r.get("test_name", "")),
                cwe=cwe,
                references=[u for u in [r.get("more_info"), (r.get("issue_cwe") or {}).get("link")] if u],
                context=_snippet(root, rel, line, end, self.cfg),
            ))
        run.findings = len(findings)
        return run, findings

    # ----- Semgrep -------------------------------------------------------- #

    def _semgrep_configs(self, root: Path) -> list[str]:
        configs = list(self.cfg.semgrep_configs)
        for local in (_PKG_RULES_DIR, root / _REPO_RULES_SUBDIR):
            if local.is_dir() and any(local.glob("*.y*ml")):
                configs.append(str(local))
        return configs

    def run_semgrep(self, target: Path, root: Path) -> tuple[ToolRun, list[Finding]]:
        run = ToolRun(tool="semgrep")
        exe = shutil.which("semgrep")
        if not exe:
            run.status, run.errors = "skipped", ["semgrep is not installed / not on PATH"]
            return run, []

        cmd = [exe, "scan", "--json", "--metrics=off", "--quiet", "--disable-version-check",
               "--timeout", "30",
               # Inside a git repo Semgrep only scans *tracked* files, so new/uncommitted
               # files would be silently skipped. We rely on --exclude below instead.
               "--no-git-ignore"]
        for c in self._semgrep_configs(root):
            cmd += ["--config", c]
        for d in self.cfg.excluded_dirs:
            cmd += ["--exclude", d]
        # Semgrep's built-in ignore list (tests/, test/, ...) is matched relative to the
        # project root (normally the git root). Making the scan target the project root
        # means a repo's own tests/ stay ignored, but scanning e.g. tests/fixtures/app
        # directly does not silently scan 0 files.
        cmd += ["--project-root", "."]
        cmd.append("." if target.is_dir() else target.name)

        t0 = time.perf_counter()
        try:
            proc = _run(cmd, self.cfg.timeout_seconds, cwd=root)
        except subprocess.TimeoutExpired:
            run.status, run.errors = "error", [f"semgrep timed out after {self.cfg.timeout_seconds}s"]
            return run, []
        run.duration_seconds = round(time.perf_counter() - t0, 2)

        data = _parse_json_stdout(proc.stdout)
        if data is None:
            run.status = "error"
            run.errors.append((proc.stderr or f"exit code {proc.returncode}").strip()[-800:])
            return run, []

        run.version = data.get("version")
        run.files_scanned = len((data.get("paths") or {}).get("scanned", []))
        if run.files_scanned == 0:
            run.errors.append("[warn] semgrep scanned 0 files (all ignored or no supported languages)")
        for err in data.get("errors", []):
            level = str(err.get("level", "error")).lower()
            msg = err.get("message") or err.get("type") or "unknown error"
            if isinstance(msg, list):
                msg = " ".join(map(str, msg))
            # Per-file syntax/timeout problems are warnings; config/network failures are fatal.
            run.errors.append(f"[{level}] {str(msg).strip()[:300]}")
            if level == "error":
                run.status = "error"

        findings = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            rel = _rel(r["path"], root)
            line = int(r.get("start", {}).get("line") or 0)
            end = int(r.get("end", {}).get("line") or line)
            rule = r.get("check_id", "semgrep")
            cwe = _norm_cwe(meta.get("cwe"))
            sev = str(extra.get("severity", "INFO"))
            conf = str(meta.get("confidence", "UNKNOWN"))
            refs = meta.get("references") or []
            if isinstance(refs, str):
                refs = [refs]
            if meta.get("source"):
                refs = [meta["source"], *refs]
            owasp = meta.get("owasp") or []
            findings.append(Finding(
                id=_finding_id("semgrep", rule, rel, line),
                tool="semgrep",
                rule_id=rule,
                title=rule.rsplit(".", 1)[-1].replace("-", " "),
                message=" ".join(str(extra.get("message", "")).split()),
                severity=_semgrep_severity(sev, conf, str(meta.get("impact", ""))),
                scanner_severity=sev,
                confidence=conf.upper(),
                file=rel, line=line, end_line=end,
                category=_category(cwe, rule),
                cwe=cwe,
                owasp=owasp if isinstance(owasp, list) else [owasp],
                references=list(dict.fromkeys(refs))[:5],
                context=_snippet(root, rel, line, end, self.cfg),
            ))
        run.findings = len(findings)
        return run, findings

    # ----- Orchestration --------------------------------------------------- #

    def scan(self, target: str | Path) -> dict[str, Any]:
        target = Path(target).resolve()
        if not target.exists():
            raise FileNotFoundError(target)
        root = target if target.is_dir() else target.parent

        runs: list[ToolRun] = []
        findings: list[Finding] = []
        if self.cfg.run_bandit:
            run, f = self.run_bandit(target, root)
            runs.append(run)
            findings += f
        if self.cfg.run_semgrep:
            run, f = self.run_semgrep(target, root)
            runs.append(run)
            findings += f
        return build_report(str(target), runs, deduplicate(findings))


def _tool_version(cmd: list[str]) -> str | None:
    try:
        out = _run(cmd, 30).stdout.strip().splitlines()
        return out[0].split()[-1] if out else None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Normalization / dedup / report
# --------------------------------------------------------------------------- #

def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge findings that describe the same weakness on the same line.

    Same (file, line, CWE) - or same (file, line, category), since Semgrep tags
    one issue with different CWEs across rule packs - becomes one finding,
    keeping the higher severity and recording the other rule in `also_reported_by`.
    Findings without a CWE or known category merge only on identical rule id.
    """
    merged: dict[tuple, Finding] = {}
    for f in findings:
        keys = [(f.file, f.line, c) for c in f.cwe]
        if f.category != "other":
            keys.append((f.file, f.line, f.category))
        keys = keys or [(f.file, f.line, f.rule_id)]
        existing = next((merged[k] for k in keys if k in merged), None)
        if existing is None:
            for k in keys:
                merged[k] = f
            continue
        if existing is f:
            continue
        if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[existing.severity]:
            existing.severity = f.severity
        if f.tool not in existing.tool.split("+"):
            existing.tool = f"{existing.tool}+{f.tool}"
        existing.also_reported_by.append(f"{f.tool}:{f.rule_id}")
        existing.cwe = sorted(set(existing.cwe) | set(f.cwe))
        existing.references = list(dict.fromkeys(existing.references + f.references))[:6]
        for k in keys:
            merged.setdefault(k, existing)
    unique = list({id(f): f for f in merged.values()}.values())
    unique.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))
    return unique


def build_report(target: str, runs: list[ToolRun], findings: list[Finding]) -> dict[str, Any]:
    counts = {k: 0 for k in ("critical", "medium", "info")}
    for f in findings:
        counts[f.severity] += 1
    tool_errors = [r for r in runs if r.status == "error"]
    ran_any = any(r.status != "skipped" for r in runs)

    if counts["critical"]:
        overall = "critical"
    elif counts["medium"] or tool_errors or not ran_any:
        overall = "medium"   # fail-safe: a failed / missing scan needs review, not a pass
    else:
        overall = "good"

    by_category: dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1

    return {
        "tool": "shipsafe-code-scanner",
        "target": target,
        "overall": overall,
        "counts": counts,
        "by_category": by_category,
        "tools": [asdict(r) for r in runs],
        "findings": [f.to_dict() for f in findings],
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

_ICON = {"critical": "[CRITICAL]", "medium": "[MEDIUM]  ", "info": "[INFO]    "}


def format_text(report: dict[str, Any], show_info: bool = False) -> str:
    out = [f"ShipSafe code scan - overall: {report['overall'].upper()}",
           f"Target: {report['target']}",
           f"Counts: {report['counts']}  by category: {report['by_category']}", ""]
    for t in report["tools"]:
        line = f"  {t['tool']:<8} {t['status']:<8} findings={t['findings']}"
        if t["version"]:
            line += f"  v{t['version']}"
        if t["duration_seconds"] is not None:
            line += f"  {t['duration_seconds']}s"
        out.append(line)
        for e in t["errors"][:5]:
            out.append(f"           ! {e}")
    out.append("")
    for f in report["findings"]:
        if f["severity"] == "info" and not show_info:
            continue
        cwe = f"  {', '.join(f['cwe'])}" if f["cwe"] else ""
        out.append(f"{_ICON[f['severity']]} {f['file']}:{f['line']}  [{f['tool']}] {f['rule_id']}{cwe}")
        out.append(f"           {f['message'][:200]}")
    hidden = report["counts"]["info"] if not show_info else 0
    if hidden:
        out.append(f"\n({hidden} info-level findings hidden; use --show-info)")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ShipSafe code scanner (Bandit + Semgrep)")
    parser.add_argument("target", help="repository directory or a single source file")
    parser.add_argument("--json", action="store_true", help="print the full JSON report")
    parser.add_argument("--no-bandit", action="store_true")
    parser.add_argument("--no-semgrep", action="store_true")
    parser.add_argument("--semgrep-config", action="append",
                        help="override Semgrep rule packs (repeatable), e.g. p/python")
    parser.add_argument("--show-info", action="store_true", help="also list info-level findings")
    args = parser.parse_args(argv)

    cfg = ScannerConfig(run_bandit=not args.no_bandit, run_semgrep=not args.no_semgrep)
    if args.semgrep_config:
        cfg.semgrep_configs = args.semgrep_config
    report = CodeScanner(cfg).scan(args.target)
    print(json.dumps(report, indent=2) if args.json else format_text(report, args.show_info))
    return {"good": 0, "medium": 2, "critical": 1}[report["overall"]]


if __name__ == "__main__":
    sys.exit(main())
