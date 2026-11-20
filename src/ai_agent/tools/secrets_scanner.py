"""ShipSafe secret scanner #2: additional secret detection with detect-secrets.

Gitleaks (gitleaks_scanner.py) is the primary secret scanner and the only one
that reads Git history. detect-secrets is a second, independent opinion over
the CURRENT files: different plugins (keyword detector, Base64/Hex entropy,
JWT, Basic-Auth URLs, IBM/Artifactory/Twilio/... token formats) and different
false-positive filters, so it catches some things Gitleaks misses and vice versa.

detect-secrets runs in-process through its Python API (it is a project
dependency, no binary needed). Every file under the target is scanned -
tracked, untracked and git-ignored - minus virtualenvs / node_modules / build
output and files over the size limit.

Findings use the same SecretFinding format as gitleaks_scanner, including
`secret_sha1` (== detect-secrets' `hashed_secret`), so the normalize node can
consolidate both tools. `merge_secret_reports()` below does exactly that.

Severity of a single secret (same rules as Gitleaks, so both tools agree):
    critical  - a known token format (AWS, GitHub, Stripe, private key, ...) or a
                high-entropy keyword match in a committed / committable file
    medium    - placeholder-looking value, test / example / docs path, or a
                generic keyword / entropy match with low entropy -> needs review
    info      - only in a git-ignored local file, marked as a false positive in
                the repo's audited .secrets.baseline, or not a credential at all
                (public IP address). Never blocks on its own.

Repo-controlled suppressions (`.secrets.baseline` audits and inline
`# pragma: allowlist secret` comments) are honoured by default but never
silently: baseline false positives stay in the report as `info`. For untrusted
Pull Requests use --ignore-baseline / --ignore-inline-allowlist.

The raw secret NEVER leaves this module (masked preview, redacted evidence and
code context only). Tool failures are never treated as "no findings": a failed
or missing detect-secrets forces the overall result to at least "medium".

CLI:
    python -m ai_agent.tools.secrets_scanner <repo_dir_or_file> [--json]
        [--ignore-baseline] [--ignore-inline-allowlist]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ai_agent.tools.code_scanner import EXCLUDED_DIRS, SEVERITY_ORDER, ToolRun, _snippet
from ai_agent.tools.gitleaks_scanner import (
    _LOW_RISK_PATH,
    _PLACEHOLDER,
    SecretFinding,
    _redact,
    git_ignored,
    git_toplevel,
    mask_secret,
)

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

BASELINE_NAMES = (".secrets.baseline", ".github/.secrets.baseline")
_INLINE_ALLOWLIST_FILTER = "detect_secrets.filters.allowlist.is_line_allowlisted"

# detect-secrets plugin types that match "keyword = something" or "random-looking
# string" rather than a known credential format -> noisy, judged by entropy.
_GENERIC_TYPES = {"Secret Keyword", "Base64 High Entropy String", "Hex High Entropy String"}
_GENERIC_MIN_ENTROPY = 3.5
_GENERIC_MIN_LENGTH = 12

# Reported by detect-secrets but not credentials.
_NOT_A_SECRET_TYPES = {"Public IP (ipv4)"}

# When several plugins flag the same value, the most specific one names the finding.
_TYPE_RANK_GENERIC = {"Secret Keyword": 1, "Base64 High Entropy String": 2,
                      "Hex High Entropy String": 2, "Public IP (ipv4)": 3}

# Binary / generated files that are never worth reading.
_SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".pdf", ".zip", ".gz",
    ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".whl", ".egg", ".exe", ".dll", ".so",
    ".dylib", ".pyc", ".pyo", ".class", ".o", ".a", ".lib", ".bin", ".dat", ".db", ".sqlite",
    ".sqlite3", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi",
    ".wav", ".ogg", ".ipynb_checkpoints", ".min.js", ".map", ".lock",
}
_SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock",
               "Pipfile.lock", "Cargo.lock", "go.sum", *BASELINE_NAMES}

# detect-secrets' settings are a process-wide singleton; serialize scans so parallel
# LangGraph nodes / FastAPI requests cannot clobber each other's configuration.
_SETTINGS_LOCK = threading.Lock()


@dataclass
class DetectSecretsConfig:
    use_baseline: bool = True               # honour <repo>/.secrets.baseline audits (FP -> info)
    honour_inline_allowlist: bool = True    # honour `# pragma: allowlist secret` comments
    disabled_plugins: list[str] = field(default_factory=list)   # e.g. ["IPPublicDetector"]
    timeout_seconds: int = 300              # whole-scan budget; partial results are kept
    max_file_kilobytes: int = 2048          # skip larger files (dumps, bundles)
    context_lines: int = 2                  # code lines around a finding for the LLM
    max_snippet_chars: int = 1200
    excluded_dirs: list[str] = field(default_factory=lambda: list(EXCLUDED_DIRS))


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class DetectSecretsFinding(SecretFinding):
    secret_types: list[str] = field(default_factory=list)   # every plugin that flagged the value
    other_lines: list[int] = field(default_factory=list)    # same value elsewhere in the file
    baseline_status: str | None = None      # "false_positive" | "confirmed" | "unaudited" | None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())


_TOKEN_CHARS = r"[A-Za-z0-9_\-+/.~]"     # no "=" (KEY=value); base64 padding handled below


def _full_token(secret: str, line_text: str) -> str:
    """Some plugins report only part of a token (GitHub Token -> 'ghp'). Expand the value to
    the whole token on its line so masking, redaction and the SHA-1 cover the real secret
    (and match Gitleaks' SHA-1 for dedup)."""
    if not secret or not line_text or secret not in line_text:
        return secret
    for m in re.finditer(f"{_TOKEN_CHARS}*{re.escape(secret)}{_TOKEN_CHARS}*=*", line_text):
        return m.group(0) if len(m.group(0)) > len(secret) else secret
    return secret


def _line_text(cache: dict[str, list[str]], root: Path, rel: str, line: int) -> str:
    if rel not in cache:
        try:
            cache[rel] = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[rel] = []
    lines = cache[rel]
    return lines[line - 1] if 0 < line <= len(lines) else ""


def _slug(secret_type: str) -> str:
    return "-".join(secret_type.lower().replace("(", "").replace(")", "").split())


def _iter_files(target: Path, cfg: DetectSecretsConfig) -> tuple[list[Path], int]:
    """Files to scan + number skipped for size / type."""
    if target.is_file():
        return [target], 0
    excluded = set(cfg.excluded_dirs)
    limit = cfg.max_file_kilobytes * 1024
    files: list[Path] = []
    skipped = 0
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded
                             and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            path = Path(dirpath, name)
            lower = name.lower()
            if (name in _SKIP_NAMES or any(lower.endswith(s) for s in _SKIP_SUFFIXES)
                    or path.is_symlink()):
                skipped += 1
                continue
            try:
                if path.stat().st_size > limit:
                    skipped += 1
                    continue
            except OSError:
                skipped += 1
                continue
            files.append(path)
    return files, skipped


def _load_baseline(root: Path) -> tuple[str | None, dict[tuple[str, str], bool | None], str | None]:
    """(path used, {(file, hashed_secret): is_secret}, error). Keys with file '' match any file."""
    for name in BASELINE_NAMES:
        path = root / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            audits: dict[tuple[str, str], bool | None] = {}
            for fname, items in (data.get("results") or {}).items():
                for item in items:
                    h = str(item.get("hashed_secret") or "")
                    if h:
                        status = item.get("is_secret")
                        audits[(Path(fname).as_posix(), h)] = status
                        audits.setdefault(("", h), status)
            return path.as_posix(), audits, None
        except (OSError, ValueError, AttributeError) as exc:
            return path.as_posix(), {}, f"could not read {name}: {exc}"
    return None, {}, None


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class DetectSecretsScanner:
    def __init__(self, config: DetectSecretsConfig | None = None):
        self.cfg = config or DetectSecretsConfig()
        self.version: str | None = None
        self.baseline_used: str | None = None

    def scan(self, target: str | Path) -> dict[str, Any]:
        target = Path(target).resolve()
        if not target.exists():
            raise FileNotFoundError(target)
        root = target if target.is_dir() else target.parent
        git_root = git_toplevel(root)
        run = ToolRun(tool="detect-secrets")

        try:
            from detect_secrets.__version__ import VERSION
            from detect_secrets.core.scan import scan_file
            from detect_secrets.settings import default_settings, get_plugins
        except ImportError as exc:
            run.status, run.errors = "skipped", [f"detect-secrets is not installed: {exc}"]
            return build_report(str(target), run, [], self, git_root)
        self.version = VERSION

        audits: dict[tuple[str, str], bool | None] = {}
        if self.cfg.use_baseline:
            self.baseline_used, audits, err = _load_baseline(git_root or root)
            if err:
                run.errors.append(f"[warn] {err}")

        files, skipped = _iter_files(target, self.cfg)
        raw: list[tuple[str, Any]] = []      # (repo-relative file, PotentialSecret)
        failed: list[str] = []
        t0 = time.perf_counter()
        scanned = 0

        with _SETTINGS_LOCK, default_settings() as settings:
            if not self.cfg.honour_inline_allowlist:
                settings.disable_filters(_INLINE_ALLOWLIST_FILTER)
            if self.cfg.disabled_plugins:
                settings.disable_plugins(*self.cfg.disabled_plugins)
            # (disable_* clear detect-secrets' caches themselves; calling cache_bust() here
            # would leave get_plugins() empty and every file would scan "clean".)
            if not get_plugins():
                run.status = "error"
                run.errors.append("detect-secrets loaded no plugins - nothing was scanned")
                files = []
            for path in files:
                if time.perf_counter() - t0 > self.cfg.timeout_seconds:
                    run.status = "error"
                    run.errors.append(f"detect-secrets timed out after {self.cfg.timeout_seconds}s "
                                      f"({scanned}/{len(files)} files scanned; partial results kept)")
                    break
                rel = path.relative_to(root).as_posix()
                try:
                    raw += [(rel, s) for s in scan_file(str(path))]
                except Exception as exc:   # one unreadable / odd file must not kill the scan
                    failed.append(f"{rel}: {type(exc).__name__}: {exc}"[:200])
                scanned += 1

        run.duration_seconds = round(time.perf_counter() - t0, 2)
        run.files_scanned = scanned
        if skipped:
            run.errors.append(f"[info] {skipped} binary / lock / oversized file(s) skipped")
        if failed:
            run.errors.append(f"[warn] {len(failed)} file(s) could not be scanned: "
                              + "; ".join(failed[:5]))
        run.findings = len(raw)

        findings = self._normalize(raw, root, git_root, audits)
        return build_report(str(target), run, findings, self, git_root)

    # ----- normalization --------------------------------------------------- #

    def _normalize(self, raw: list[tuple[str, Any]], root: Path, git_root: Path | None,
                   audits: dict[tuple[str, str], bool | None]) -> list[DetectSecretsFinding]:
        # One finding per (file, secret value); every plugin / line that saw it is merged in.
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        file_lines: dict[str, list[str]] = {}
        for rel, s in raw:
            secret = _full_token(str(s.secret_value or ""),
                                 _line_text(file_lines, root, rel, int(s.line_number or 0)))
            sha1 = hashlib.sha1(secret.encode("utf-8", "replace")).hexdigest()
            g = groups.setdefault((rel, sha1), {"secret": secret, "types": [], "lines": [],
                                                "ds_hashes": {sha1}})
            g["ds_hashes"].add(s.secret_hash)    # what .secrets.baseline audits refer to
            if s.type not in g["types"]:
                g["types"].append(s.type)
            if s.line_number and s.line_number not in g["lines"]:
                g["lines"].append(int(s.line_number))

        findings: list[DetectSecretsFinding] = []
        for (rel, sha1), g in groups.items():
            secret = g["secret"]
            types = sorted(g["types"], key=lambda t: _TYPE_RANK_GENERIC.get(t, 0))
            primary = types[0]
            lines = sorted(g["lines"]) or [0]
            entropy = round(shannon_entropy(secret), 2)
            confidence = ("HIGH" if primary not in _TYPE_RANK_GENERIC
                          else "MEDIUM" if primary == "Secret Keyword" else "LOW")
            baseline_status = None
            if audits:
                keys = [(rel, h) for h in g["ds_hashes"]] + [("", h) for h in g["ds_hashes"]]
                audit = next((audits[k] for k in keys if k in audits), None)
                baseline_status = {True: "confirmed", False: "false_positive"}.get(audit, "unaudited")

            f = DetectSecretsFinding(
                id=hashlib.sha256(f"detect-secrets|{rel}|{sha1}".encode()).hexdigest()[:10],
                tool="detect-secrets",
                rule_id=_slug(primary),
                title=primary,
                message="",
                severity="critical",
                scanner_severity="SECRET",
                confidence=confidence,
                file=rel, line=lines[0], end_line=lines[0],
                category="secrets" if primary not in _NOT_A_SECRET_TYPES else "other",
                cwe=["CWE-798"] if primary not in _NOT_A_SECRET_TYPES else [],
                references=["https://cwe.mitre.org/data/definitions/798.html"]
                if primary not in _NOT_A_SECRET_TYPES else [],
                also_reported_by=[_slug(t) for t in types[1:]],
                secret_preview=mask_secret(secret),
                secret_sha1=sha1,
                entropy=entropy,
                in_working_tree=True,
                in_history=None,          # detect-secrets does not read history (Gitleaks does)
                secret_types=types,
                other_lines=lines[1:],
                baseline_status=baseline_status,
            )
            f._secret = secret  # type: ignore[attr-defined]
            findings.append(f)

        # A snippet can show neighbouring secrets too, so redact every secret of that file.
        per_file: dict[str, list[str]] = {}
        for f in findings:
            per_file.setdefault(f.file, []).append(f._secret)  # type: ignore[attr-defined]

        ignored = git_ignored(root, [f.file for f in findings]) if git_root else set()
        for f in findings:
            secret = f._secret  # type: ignore[attr-defined]
            del f._secret  # type: ignore[attr-defined]
            f.git_ignored = f.file in ignored
            context = _snippet(root, f.file, f.line, f.end_line, self.cfg)
            for s in sorted(per_file[f.file], key=len, reverse=True):
                context = _redact(context, s)
            f.context = context
            f.evidence = _evidence_line(f.context, f.line)
            self._assess(f, secret)

        findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))
        return findings

    @staticmethod
    def _assess(f: DetectSecretsFinding, secret: str) -> None:
        """Deterministic severity + human-readable reasons (the LLM never sees `secret`)."""
        reasons: list[str] = []
        sev = "critical"

        if f.title in _NOT_A_SECRET_TYPES:
            sev = "info"
            reasons.append("public IP address, not a credential (review only if it exposes "
                           "internal infrastructure)")
        elif f.baseline_status == "false_positive":
            sev = "info"
            reasons.append("audited as a false positive in the repo's .secrets.baseline "
                           "(the audit itself is repo-controlled - check it on untrusted PRs)")
        elif f.git_ignored:
            sev = "info"
            reasons.append("file is git-ignored (local only); Gitleaks checks whether it was "
                           "ever committed")
        else:
            if _LOW_RISK_PATH.search(f.file):
                sev = "medium"
                reasons.append("located in a test / example / docs path")
            if _PLACEHOLDER.search(secret):
                sev = "medium"
                reasons.append("value looks like a placeholder")
            if f.title in _GENERIC_TYPES and (
                    (f.entropy or 0) < _GENERIC_MIN_ENTROPY or len(secret) < _GENERIC_MIN_LENGTH):
                sev = "medium"
                reasons.append(f"generic {f.title.lower()} match with low entropy / short value "
                               f"(entropy {f.entropy}, {len(secret)} chars)")
            if f.baseline_status == "confirmed":
                reasons.append("confirmed as a real secret in the .secrets.baseline audit")
            if sev == "critical":
                reasons.append("known credential format" if f.confidence == "HIGH"
                               else "high-entropy value assigned to a secret-like name")
                reasons.append("in a committed or committable file")

        if len(f.secret_types) > 1:
            reasons.append("also matched by: " + ", ".join(f.secret_types[1:]))

        where = f"{f.file}:{f.line}"
        if f.other_lines:
            where += f" (+ line{'s' if len(f.other_lines) > 1 else ''} "
            where += ", ".join(map(str, f.other_lines[:5])) + ")"
        f.severity = sev
        f.severity_reasons = reasons
        f.message = f"{f.title}: {f.secret_preview} found at {where}."

        if f.title in _NOT_A_SECRET_TYPES:
            f.remediation = "No action needed unless the address is internal or sensitive."
        elif sev == "info" and f.git_ignored:
            f.remediation = "Keep the file out of version control; never commit it."
        elif sev == "info":
            f.remediation = "No action if the baseline audit is correct."
        else:
            f.remediation = ("Remove the credential from the code and load it from an environment "
                             "variable or secret manager. If it is real and was ever committed or "
                             "shared, revoke/rotate it. If it is a false positive, add it to "
                             ".secrets.baseline and audit it (`detect-secrets audit`).")


def _evidence_line(context: str, line: int) -> str:
    """The (already redacted) flagged line from the snippet, without its line-number gutter."""
    for row in context.splitlines():
        if row.startswith(">") and row[1:].split("|", 1)[0].strip() == str(line):
            return row.split("|", 1)[1].strip()[:300] if "|" in row else ""
    return ""


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def build_report(target: str, run: ToolRun, findings: list[DetectSecretsFinding],
                 scanner: DetectSecretsScanner, git_root: Path | None) -> dict[str, Any]:
    counts = {k: 0 for k in ("critical", "medium", "info")}
    for f in findings:
        counts[f.severity] += 1

    if counts["critical"]:
        overall = "critical"
    elif counts["medium"] or run.status != "ok":
        overall = "medium"   # fail-safe: a failed / missing scan needs review, not a pass
    else:
        overall = "good"

    return {
        "tool": "shipsafe-detect-secrets-scanner",
        "target": target,
        "git_root": git_root.as_posix() if git_root else None,
        "detect_secrets_version": scanner.version,
        "baseline_used": scanner.baseline_used,
        "inline_allowlist_honoured": scanner.cfg.honour_inline_allowlist,
        "overall": overall,
        "counts": counts,
        "tools": [asdict(run)],
        "findings": [f.to_dict() for f in findings],
    }


def scan_secrets_detect(target: str | Path, **config: Any) -> dict[str, Any]:
    """Convenience entry point for the LangGraph node / FastAPI backend."""
    return DetectSecretsScanner(DetectSecretsConfig(**config)).scan(target)


def merge_secret_reports(gitleaks_report: dict[str, Any] | None,
                         detect_report: dict[str, Any] | None) -> dict[str, Any]:
    """Consolidate Gitleaks + detect-secrets into one list of secret findings.

    The same value in the same file (matched on `secret_sha1`) becomes one finding:
    the Gitleaks one (it knows about Git history) with "detect-secrets:<rule>" in
    `also_reported_by` and the stricter of the two severities. Everything only
    detect-secrets found is added as-is. Both reports must use the same target.
    """
    gl = [dict(f) for f in (gitleaks_report or {}).get("findings", [])]
    ds = (detect_report or {}).get("findings", [])
    by_key = {(f["file"], f["secret_sha1"]): f for f in gl}
    merged = list(gl)
    for f in ds:
        twin = by_key.get((f["file"], f["secret_sha1"]))
        if twin is None:
            merged.append(dict(f))
            continue
        twin["also_reported_by"] = sorted({*twin.get("also_reported_by", []),
                                           f"detect-secrets:{f['rule_id']}"})
        if SEVERITY_ORDER[f["severity"]] > SEVERITY_ORDER[twin["severity"]]:
            twin["severity"] = f["severity"]
            twin["severity_reasons"] = [*twin.get("severity_reasons", []),
                                        "raised by detect-secrets: " + "; ".join(f["severity_reasons"])]
    merged.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["file"], f["line"]))

    counts = {k: 0 for k in ("critical", "medium", "info")}
    for f in merged:
        counts[f["severity"]] += 1
    overalls = [r.get("overall", "medium") for r in (gitleaks_report, detect_report) if r]
    overall = max(overalls or ["medium"], key=SEVERITY_ORDER.__getitem__)
    if counts["critical"]:
        overall = "critical"
    return {
        "tool": "shipsafe-secrets",
        "overall": overall,
        "counts": counts,
        "tools": [t for r in (gitleaks_report, detect_report) if r for t in r.get("tools", [])],
        "findings": merged,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

_ICON = {"critical": "[CRITICAL]", "medium": "[MEDIUM]  ", "info": "[INFO]    "}


def format_text(report: dict[str, Any]) -> str:
    out = [f"ShipSafe secret scan (detect-secrets {report['detect_secrets_version'] or '?'}) - "
           f"overall: {report['overall'].upper()}",
           f"Target: {report['target']}",
           f"Counts: {report['counts']}"]
    if report["baseline_used"]:
        out.append(f"Baseline honoured: {report['baseline_used']}  (check its audits!)")
    if not report["inline_allowlist_honoured"]:
        out.append("Inline `pragma: allowlist secret` comments ignored")
    out.append("")
    for t in report["tools"]:
        line = f"  {t['tool']:<15} {t['status']:<8} findings={t['findings']}"
        if t["files_scanned"] is not None:
            line += f"  files={t['files_scanned']}"
        if t["duration_seconds"] is not None:
            line += f"  {t['duration_seconds']}s"
        out.append(line)
        for e in t["errors"][:5]:
            out.append(f"           ! {e}")
    out.append("")
    for f in report["findings"]:
        out.append(f"{_ICON[f['severity']]} {f['file']}:{f['line']}  {f['rule_id']}  {f['secret_preview']}")
        out.append(f"           {f['message']}")
        if f["evidence"]:
            out.append(f"           line: {f['evidence']}")
        out.append(f"           why: {'; '.join(f['severity_reasons'])}")
        out.append(f"           fix: {f['remediation']}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ShipSafe secret scanner (detect-secrets, current files)")
    parser.add_argument("target", help="repository directory or a single file")
    parser.add_argument("--json", action="store_true", help="print the full JSON report")
    parser.add_argument("--ignore-baseline", action="store_true",
                        help="do not honour the repo's .secrets.baseline audits (untrusted PRs)")
    parser.add_argument("--ignore-inline-allowlist", action="store_true",
                        help="do not honour `pragma: allowlist secret` comments (untrusted PRs)")
    parser.add_argument("--disable-plugin", action="append", default=[],
                        help="detect-secrets plugin class to disable, e.g. IPPublicDetector")
    args = parser.parse_args(argv)

    cfg = DetectSecretsConfig(use_baseline=not args.ignore_baseline,
                              honour_inline_allowlist=not args.ignore_inline_allowlist,
                              disabled_plugins=args.disable_plugin)
    report = DetectSecretsScanner(cfg).scan(args.target)
    print(json.dumps(report, indent=2) if args.json else format_text(report))
    return {"good": 0, "medium": 2, "critical": 1}[report["overall"]]


if __name__ == "__main__":
    sys.exit(main())
