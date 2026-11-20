"""ShipSafe secret scanner: Gitleaks over the working tree AND the Git history.

Two Gitleaks passes, merged into one result:

    files    - `gitleaks dir`  : every file on disk now (incl. untracked files),
               minus virtualenvs / node_modules / build output.
    history  - `gitleaks git`  : every commit reachable from HEAD (or a range
               such as `origin/main..HEAD` for a Pull Request). A secret that
               was committed and later deleted is still leaked - anyone with
               the repo can read it - so it still has to be rotated.

The same secret found by both passes (or in many commits) becomes ONE finding
that records where it was seen (`in_working_tree`, `in_history`, `commits`).

Findings use the common format of code_scanner.Finding (+ secret-specific
fields), so the rest of the pipeline (dedup -> LLM triage -> policy -> PR
report) treats them like any other finding.

Severity of a single secret:
    critical  - a real-looking credential in a committed / committable file,
                or anywhere in Git history
    medium    - likely a placeholder / test value, lives in a test, example or
                docs path, or a low-entropy "generic" match -> needs review
    info      - only in a git-ignored local file (e.g. .env) and never
                committed: present on this machine, but not leaked

The raw secret NEVER leaves this module: findings carry a masked preview
(`AKIA****************  (20 chars)`), the masked match, and a SHA-1 of the
secret (`secret_sha1`, same as detect-secrets' `hashed_secret`, used for
cross-tool dedup - do not print it in PR comments).

Tool failures are never treated as "no findings": a failed or missing
Gitleaks forces the overall result to at least "medium" (report section 13).

Install Gitleaks (single Go binary): https://github.com/gitleaks/gitleaks/releases
or `winget install gitleaks` / `brew install gitleaks`. Set GITLEAKS_PATH to
use a binary that is not on PATH.

CLI:
    python -m ai_agent.tools.gitleaks_scanner <repo_dir_or_file> [--json]
        [--mode both|files|history] [--log-opts "origin/main..HEAD"]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ai_agent.tools.code_scanner import (
    EXCLUDED_DIRS,
    SEVERITY_ORDER,
    Finding,
    ToolRun,
    _rel,
    _run,
    _snippet,
)

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

MODES = ("both", "files", "history")

# Gitleaks >= 8.19 has `git` / `dir`; older v8 releases only have `detect`.
_NEW_CLI_VERSION = (8, 19, 0)

# Paths where a secret is more likely a fixture or sample value (-> review, not block).
_LOW_RISK_PATH = re.compile(
    r"(^|/)(tests?|testing|spec|specs|__tests__|fixtures?|examples?|samples?|docs?|mocks?)(/|$)"
    r"|\.(example|sample|template|dist)$"
    r"|(^|/)[^/]*(_test|\.test|\.spec|test_)[^/]*$",
    re.IGNORECASE,
)

# Values that look like placeholders rather than live credentials.
_PLACEHOLDER = re.compile(
    r"example|placeholder|changeme|change_me|dummy|sample|your[_-]?(api|secret|token|key|pass)"
    r"|x{4,}|\*{4,}|<[^>]+>|\$\{[^}]*\}|\{\{[^}]*\}\}|^(.)\2+$",
    re.IGNORECASE,
)

# Rules that match "keyword = high-entropy string" rather than a known token format.
_GENERIC_RULES = {"generic-api-key", "generic-secret", "generic-password"}
_GENERIC_MIN_ENTROPY = 3.5


@dataclass
class GitleaksConfig:
    mode: str = "both"                      # both | files | history
    gitleaks_path: str | None = None        # default: $GITLEAKS_PATH or `gitleaks` on PATH
    log_opts: str | None = None             # e.g. "--all" or "origin/main..HEAD"
    use_repo_config: bool = True            # honour <repo>/.gitleaks.toml (rules + allowlist)
    timeout_seconds: int = 600
    max_target_megabytes: int = 5           # skip larger files (binaries, dumps)
    context_lines: int = 2                  # code lines around a finding for the LLM
    max_snippet_chars: int = 1200
    excluded_dirs: list[str] = field(default_factory=lambda: list(EXCLUDED_DIRS))


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class SecretFinding(Finding):
    secret_preview: str = ""                # masked, safe to show
    evidence: str = ""                      # masked matched text, safe to show
    secret_sha1: str = ""                   # == detect-secrets hashed_secret; for dedup only
    entropy: float | None = None
    in_working_tree: bool | None = None     # None = files pass did not run
    in_history: bool | None = None          # None = history pass did not run
    git_ignored: bool = False               # file is ignored by .gitignore (local only)
    commits: list[dict[str, str]] = field(default_factory=list)   # [{commit, author, date, message}]
    severity_reasons: list[str] = field(default_factory=list)
    remediation: str = ""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def mask_secret(secret: str) -> str:
    """Show enough to recognise a key type, never enough to use it."""
    s = secret.strip()
    if not s:
        return ""
    if "PRIVATE KEY" in s:
        return f"-----BEGIN ... PRIVATE KEY----- ****  ({len(s)} chars)"
    keep = 4 if len(s) >= 16 else (2 if len(s) >= 8 else 0)
    return f"{s[:keep]}{'*' * min(16, len(s) - keep)}  ({len(s)} chars)"


def _redact(text: str, secret: str) -> str:
    """Replace every line of the secret inside `text` with asterisks."""
    if not text or not secret:
        return text
    parts = [p.strip() for p in secret.splitlines() if len(p.strip()) >= 4] or [secret]
    for p in sorted(parts, key=len, reverse=True):
        text = text.replace(p, "*" * min(len(p), 20))
    return text


def _parse_version(text: str) -> tuple[int, ...] | None:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _git(args: list[str], cwd: Path, stdin: str | None = None) -> subprocess.CompletedProcess | None:
    exe = shutil.which("git")
    if not exe:
        return None
    try:
        return subprocess.run([exe, *args], cwd=cwd, input=stdin, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None


def git_toplevel(path: Path) -> Path | None:
    proc = _git(["rev-parse", "--show-toplevel"], path if path.is_dir() else path.parent)
    if proc is None or proc.returncode != 0 or not proc.stdout.strip():
        return None
    return Path(proc.stdout.strip()).resolve()


def git_ignored(root: Path, rel_files: list[str]) -> set[str]:
    """Subset of `rel_files` (relative to root) that .gitignore excludes and git does not track."""
    if not rel_files:
        return set()
    # NUL-separated: text-mode stdin on Windows would turn "\n" into "\r\n" and break matching.
    proc = _git(["check-ignore", "-z", "--stdin"], root, stdin="\0".join(rel_files) + "\0")
    if proc is None or proc.returncode not in (0, 1):   # 1 = nothing ignored
        return set()
    return {Path(p).as_posix() for p in proc.stdout.split("\0") if p.strip()}


def _path_regex(dirname: str) -> str:
    return r"(?:^|[\\/])" + re.escape(dirname) + r"(?:[\\/]|$)"


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class GitleaksScanner:
    def __init__(self, config: GitleaksConfig | None = None):
        self.cfg = config or GitleaksConfig()
        if self.cfg.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.exe = self.cfg.gitleaks_path or os.environ.get("GITLEAKS_PATH") or shutil.which("gitleaks")
        self.version: str | None = None
        self.repo_config_used: str | None = None

    # ----- binary / config ------------------------------------------------- #

    def _detect_version(self) -> tuple[int, ...] | None:
        try:
            proc = _run([self.exe, "version"], 30)
        except (OSError, subprocess.TimeoutExpired):
            return None
        parsed = _parse_version(proc.stdout or proc.stderr)
        self.version = ".".join(map(str, parsed)) if parsed else None
        return parsed

    def _write_config(self, root: Path, tmpdir: Path) -> Path:
        """Default rules (or the repo's own .gitleaks.toml) + an allowlist for excluded dirs."""
        repo_cfg = next((root / n for n in (".gitleaks.toml", ".github/.gitleaks.toml")
                         if (root / n).is_file()), None) if self.cfg.use_repo_config else None
        if repo_cfg:
            self.repo_config_used = repo_cfg.as_posix()
            extend = f"[extend]\npath = '''{repo_cfg.resolve().as_posix()}'''\n"
        else:
            extend = "[extend]\nuseDefault = true\n"
        paths = ",\n  ".join(f"'''{_path_regex(d)}'''" for d in self.cfg.excluded_dirs)
        text = (f'title = "shipsafe"\n\n{extend}\n'
                f'[allowlist]\ndescription = "ShipSafe: not application code"\n'
                f"paths = [\n  {paths}\n]\n")
        path = tmpdir / "shipsafe-gitleaks.toml"
        path.write_text(text, encoding="utf-8")
        return path

    # ----- one gitleaks pass ---------------------------------------------- #

    def _run_pass(self, kind: str, source: Path, cwd: Path, config: Path, tmpdir: Path,
                  new_cli: bool) -> tuple[ToolRun, list[dict]]:
        run = ToolRun(tool=f"gitleaks-{kind}", version=self.version)
        report_path = tmpdir / f"{kind}.json"
        if new_cli:
            cmd = [self.exe, "dir" if kind == "files" else "git", str(source)]
        else:
            cmd = [self.exe, "detect", "--source", str(source)]
            if kind == "files":
                cmd.append("--no-git")
        cmd += ["--config", str(config), "--report-format", "json", "--report-path", str(report_path),
                "--exit-code", "0", "--no-banner", "--log-level", "error",
                "--max-target-megabytes", str(self.cfg.max_target_megabytes)]
        if kind == "history" and self.cfg.log_opts:
            cmd.append(f"--log-opts={self.cfg.log_opts}")

        t0 = time.perf_counter()
        try:
            proc = _run(cmd, self.cfg.timeout_seconds, cwd=cwd)
        except subprocess.TimeoutExpired:
            run.status, run.errors = "error", [f"gitleaks timed out after {self.cfg.timeout_seconds}s"]
            return run, []
        except OSError as exc:
            run.status, run.errors = "error", [f"could not start gitleaks: {exc}"]
            return run, []
        run.duration_seconds = round(time.perf_counter() - t0, 2)

        # With --exit-code 0, any non-zero exit means gitleaks itself failed.
        if proc.returncode != 0:
            run.status = "error"
            run.errors.append((proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()[-800:])
            return run, []
        try:
            data = json.loads(report_path.read_text(encoding="utf-8") or "[]")
        except (OSError, ValueError) as exc:
            run.status, run.errors = "error", [f"could not read gitleaks report: {exc}"]
            return run, []
        if not isinstance(data, list):
            run.status, run.errors = "error", ["unexpected gitleaks report format"]
            return run, []
        run.findings = len(data)
        return run, data

    # ----- orchestration --------------------------------------------------- #

    def scan(self, target: str | Path) -> dict[str, Any]:
        target = Path(target).resolve()
        if not target.exists():
            raise FileNotFoundError(target)
        root = target if target.is_dir() else target.parent
        git_root = git_toplevel(root)

        runs: list[ToolRun] = []
        raw: list[tuple[str, dict]] = []      # (kind, gitleaks record)
        want_files = self.cfg.mode in ("both", "files")
        want_history = self.cfg.mode in ("both", "history")

        if not self.exe:
            msg = "gitleaks is not installed / not on PATH (set GITLEAKS_PATH)"
            for kind, wanted in (("files", want_files), ("history", want_history)):
                if wanted:
                    runs.append(ToolRun(tool=f"gitleaks-{kind}", status="skipped", errors=[msg]))
            return build_report(str(target), runs, [], self, git_root)

        parsed = self._detect_version()
        new_cli = parsed is None or parsed >= _NEW_CLI_VERSION

        with tempfile.TemporaryDirectory(prefix="shipsafe-gitleaks-") as td:
            tmpdir = Path(td)
            config = self._write_config(git_root or root, tmpdir)
            if want_files:
                run, data = self._run_pass("files", target if target.is_file() else Path("."),
                                           root, config, tmpdir, new_cli)
                runs.append(run)
                raw += [("files", r) for r in data]
            if want_history:
                if git_root is None:
                    runs.append(ToolRun(tool="gitleaks-history", status="skipped",
                                        errors=["target is not inside a git repository"]))
                else:
                    run, data = self._run_pass("history", git_root, git_root, config, tmpdir, new_cli)
                    runs.append(run)
                    raw += [("history", r) for r in data]

        files_ran = any(r.tool == "gitleaks-files" and r.status == "ok" for r in runs)
        history_ran = any(r.tool == "gitleaks-history" and r.status == "ok" for r in runs)
        findings = self._normalize(raw, root, git_root, files_ran, history_ran, runs)
        return build_report(str(target), runs, findings, self, git_root)

    # ----- normalization --------------------------------------------------- #

    def _normalize(self, raw: list[tuple[str, dict]], root: Path, git_root: Path | None,
                   files_ran: bool, history_ran: bool, runs: list[ToolRun]) -> list[SecretFinding]:
        merged: dict[tuple[str, str, str], SecretFinding] = {}
        outside_scope = 0

        for kind, r in raw:
            secret = str(r.get("Secret") or "")
            file_raw = str(r.get("File") or "")
            if kind == "history" and git_root is not None:
                rel = _rel(str(git_root / file_raw), root)
                if Path(rel).is_absolute():          # committed outside the scanned sub-folder
                    outside_scope += 1
                    continue
            else:
                rel = _rel(file_raw, root)
            rule = str(r.get("RuleID") or "gitleaks")
            sha1 = hashlib.sha1(secret.encode("utf-8", "replace")).hexdigest()
            key = (rel, rule, sha1)
            line = int(r.get("StartLine") or 0)
            end = int(r.get("EndLine") or line)

            f = merged.get(key)
            if f is None:
                f = merged[key] = SecretFinding(
                    id=hashlib.sha256(f"gitleaks|{rule}|{rel}|{sha1}".encode()).hexdigest()[:10],
                    tool="gitleaks",
                    rule_id=rule,
                    title=str(r.get("Description") or rule),
                    message="",
                    severity="critical",
                    scanner_severity="SECRET",
                    confidence="HIGH" if rule not in _GENERIC_RULES else "MEDIUM",
                    file=rel, line=line, end_line=end,
                    category="secrets",
                    cwe=["CWE-798"],
                    references=["https://cwe.mitre.org/data/definitions/798.html"],
                    secret_preview=mask_secret(secret),
                    evidence=_redact(str(r.get("Match") or ""), secret)[:300],
                    secret_sha1=sha1,
                    entropy=round(float(r["Entropy"]), 2) if r.get("Entropy") is not None else None,
                    in_working_tree=False if files_ran else None,
                    in_history=False if history_ran else None,
                )
            if kind == "files":
                f.in_working_tree = True
                f.line, f.end_line = line, end       # current location wins over historic one
            else:
                f.in_history = True
                if not f.in_working_tree:
                    f.line, f.end_line = line, end
                commit = {k.lower(): str(r.get(k) or "") for k in ("Commit", "Author", "Date")}
                msg_lines = str(r.get("Message") or "").strip().splitlines()
                commit["message"] = msg_lines[0][:120] if msg_lines else ""
                if commit["commit"] and commit["commit"] not in {c["commit"] for c in f.commits}:
                    f.commits.append(commit)
            # Keep the secret only long enough to redact the code snippet.
            f._secret = secret  # type: ignore[attr-defined]

        if outside_scope:
            for run in runs:
                if run.tool == "gitleaks-history":
                    run.errors.append(f"[info] {outside_scope} history finding(s) outside the "
                                      "scanned folder were ignored")

        findings = list(merged.values())
        ignored = git_ignored(root, [f.file for f in findings if f.in_working_tree]) if git_root else set()
        for f in findings:
            secret = getattr(f, "_secret", "")
            del f._secret  # type: ignore[attr-defined]
            f.git_ignored = f.file in ignored
            if f.in_working_tree:
                f.context = _redact(_snippet(root, f.file, f.line, f.end_line, self.cfg), secret)
            self._assess(f, secret)

        findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))
        return findings

    @staticmethod
    def _assess(f: SecretFinding, secret: str) -> None:
        """Deterministic severity + human-readable reasons (the LLM never sees `secret`)."""
        reasons: list[str] = []
        sev = "critical"

        if f.git_ignored and not f.in_history:
            sev = "info"
            reasons.append("file is git-ignored and the secret was never committed (local only)")
        else:
            if _LOW_RISK_PATH.search(f.file):
                sev = "medium"
                reasons.append("located in a test / example / docs path")
            if _PLACEHOLDER.search(secret):
                sev = "medium"
                reasons.append("value looks like a placeholder")
            if f.rule_id in _GENERIC_RULES and (f.entropy or 0) < _GENERIC_MIN_ENTROPY:
                sev = "medium"
                reasons.append(f"generic keyword match with low entropy ({f.entropy})")
            if sev == "critical":
                reasons.append("real-looking credential in a committed or committable file"
                               if f.in_working_tree else "credential is readable in Git history")

        where = []
        if f.in_working_tree:
            where.append("current files" + (" (git-ignored)" if f.git_ignored else ""))
        if f.in_history:
            n = len(f.commits)
            where.append(f"Git history ({n} commit{'s' if n != 1 else ''})")
        f.severity = sev
        f.severity_reasons = reasons
        f.message = f"{f.title}: {f.secret_preview} found in {' and '.join(where) or 'repository'}."

        if f.in_history and not f.in_working_tree:
            f.remediation = ("The secret was removed from the code but is still in Git history. "
                             "Revoke/rotate it now; optionally purge history (git filter-repo) and "
                             "force-push. Removing the line alone does not un-leak it.")
        elif f.in_history:
            f.remediation = ("Revoke/rotate the credential, move it to an environment variable or "
                             "secret manager, and remove it from the code. It is already in Git "
                             "history, so rotation is required even after removal.")
        elif f.git_ignored:
            f.remediation = "Keep the file out of version control; never commit it."
        else:
            f.remediation = ("Remove the credential from the code before committing; load it from an "
                             "environment variable or secret manager. Rotate it if it was ever shared.")


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def build_report(target: str, runs: list[ToolRun], findings: list[SecretFinding],
                 scanner: GitleaksScanner, git_root: Path | None) -> dict[str, Any]:
    counts = {k: 0 for k in ("critical", "medium", "info")}
    for f in findings:
        counts[f.severity] += 1
    tool_errors = [r for r in runs if r.status == "error"]
    ran_any = any(r.status == "ok" for r in runs)

    if counts["critical"]:
        overall = "critical"
    elif counts["medium"] or tool_errors or not ran_any:
        overall = "medium"   # fail-safe: a failed / missing scan needs review, not a pass
    else:
        overall = "good"

    return {
        "tool": "shipsafe-gitleaks-scanner",
        "target": target,
        "git_root": git_root.as_posix() if git_root else None,
        "mode": scanner.cfg.mode,
        "log_opts": scanner.cfg.log_opts,
        "gitleaks_version": scanner.version,
        "repo_config_used": scanner.repo_config_used,
        "overall": overall,
        "counts": counts,
        "secrets_in_history_only": sum(1 for f in findings if f.in_history and not f.in_working_tree),
        "tools": [asdict(r) for r in runs],
        "findings": [f.to_dict() for f in findings],
    }


def scan_secrets(target: str | Path, **config: Any) -> dict[str, Any]:
    """Convenience entry point for the LangGraph node / FastAPI backend."""
    return GitleaksScanner(GitleaksConfig(**config)).scan(target)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

_ICON = {"critical": "[CRITICAL]", "medium": "[MEDIUM]  ", "info": "[INFO]    "}


def format_text(report: dict[str, Any]) -> str:
    out = [f"ShipSafe secret scan (gitleaks {report['gitleaks_version'] or '?'}) - "
           f"overall: {report['overall'].upper()}",
           f"Target: {report['target']}   mode: {report['mode']}"
           + (f"   log-opts: {report['log_opts']}" if report["log_opts"] else ""),
           f"Counts: {report['counts']}   only in history: {report['secrets_in_history_only']}"]
    if report["repo_config_used"]:
        out.append(f"Repo config honoured: {report['repo_config_used']}  (check its allowlist!)")
    out.append("")
    for t in report["tools"]:
        line = f"  {t['tool']:<17} {t['status']:<8} findings={t['findings']}"
        if t["duration_seconds"] is not None:
            line += f"  {t['duration_seconds']}s"
        out.append(line)
        for e in t["errors"][:5]:
            out.append(f"           ! {e}")
    out.append("")
    for f in report["findings"]:
        out.append(f"{_ICON[f['severity']]} {f['file']}:{f['line']}  {f['rule_id']}  {f['secret_preview']}")
        out.append(f"           {f['message']}")
        for c in f["commits"][:3]:
            out.append(f"           commit {c['commit'][:10]} {c['date'][:10]} {c['author']}: {c['message']}")
        out.append(f"           why: {'; '.join(f['severity_reasons'])}")
        out.append(f"           fix: {f['remediation']}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ShipSafe secret scanner (Gitleaks: files + Git history)")
    parser.add_argument("target", help="repository directory or a single file")
    parser.add_argument("--json", action="store_true", help="print the full JSON report")
    parser.add_argument("--mode", choices=MODES, default="both",
                        help="scan current files, Git history, or both (default)")
    parser.add_argument("--log-opts", help='git log range for the history pass, e.g. "origin/main..HEAD"')
    parser.add_argument("--gitleaks", help="path to the gitleaks binary")
    parser.add_argument("--ignore-repo-config", action="store_true",
                        help="do not honour the repo's .gitleaks.toml (untrusted PRs)")
    args = parser.parse_args(argv)

    cfg = GitleaksConfig(mode=args.mode, log_opts=args.log_opts, gitleaks_path=args.gitleaks,
                         use_repo_config=not args.ignore_repo_config)
    report = GitleaksScanner(cfg).scan(args.target)
    print(json.dumps(report, indent=2) if args.json else format_text(report))
    return {"good": 0, "medium": 2, "critical": 1}[report["overall"]]


if __name__ == "__main__":
    sys.exit(main())
