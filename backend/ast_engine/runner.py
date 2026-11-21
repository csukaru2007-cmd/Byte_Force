"""Select the files to parse, run Clang on each, and collect features and parse problems."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from backend import config
from backend.ast_engine.ast_extractor import ASTExtractor, ProjectFeatures
from backend.ast_engine.clang_parser import ClangParser, ParseResult, clang_status
from backend.ast_engine.compile_context import CompileContext, build_context
from backend.models import ScanIssue
from backend.platformio.ini_parser import EnvironmentInfo

TU_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".ino"}
HEADER_EXTENSIONS = {".h", ".hh", ".hpp", ".hxx"}
SKIP_DIRS = {"test", "tests", "example", "examples", "extras", "docs", "doc", ".git", "build", "__macosx"}


@dataclass
class ASTAnalysis:
    features: ProjectFeatures
    context: CompileContext | None
    parse_results: list[ParseResult] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)
    available: bool = True

    def summary(self, root: Path) -> dict:
        statuses: dict[str, int] = {}
        for result in self.parse_results:
            statuses[result.status] = statuses.get(result.status, 0) + 1
        return {
            "clang": clang_status(),
            "compile_context": self.context.to_dict(root) if self.context else None,
            "files_parsed": len(self.parse_results),
            "status_counts": statuses,
            "files": [r.to_dict() for r in self.parse_results],
            "skipped": self.skipped,
            "feature_summary": [f.summary() for f in self.features.files.values()],
        }


def _candidates(base: Path, root: Path, extensions: set[str]) -> list[Path]:
    if not base.is_dir():
        return []
    found = []
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in extensions:
            continue
        inner = path.relative_to(base).parts[:-1]
        if any(part.lower() in SKIP_DIRS for part in inner):
            continue
        found.append(path)
    return found


def select_sources(root: Path, env: EnvironmentInfo | None) -> tuple[list[Path], list[Path]]:
    """Return (translation units, project headers to parse on their own if never included)."""
    units = _candidates(root / "src", root, TU_EXTENSIONS)
    units += [p for p in sorted(root.glob("*.ino"))]
    lib = root / "lib"
    if lib.is_dir():
        units += _candidates(lib, root, TU_EXTENSIONS)
    libdeps = root / ".pio" / "libdeps"
    if libdeps.is_dir():
        env_dirs = [libdeps / env.name] if env and (libdeps / env.name).is_dir() else \
            sorted(p for p in libdeps.iterdir() if p.is_dir())
        for env_dir in env_dirs:
            units += _candidates(env_dir, root, TU_EXTENSIONS)
    headers = _candidates(root / "src", root, HEADER_EXTENSIONS) + _candidates(root / "include", root, HEADER_EXTENSIONS)
    return units, headers


def analyse_sources(root: Path, env: EnvironmentInfo | None, work_dir: Path,
                    deadline: float | None = None) -> ASTAnalysis:
    status = clang_status()
    if not status["available"]:
        issue = ScanIssue("parser", f"Clang is not available ({status.get('error')}); source analysis skipped.")
        return ASTAnalysis(ProjectFeatures(), None, issues=[issue], available=False)

    context = build_context(root, env, work_dir)
    parser = ClangParser(context, root)
    extractor = ASTExtractor(root)
    analysis = ASTAnalysis(extractor.features, context)
    units, headers = select_sources(root, env)

    def run(path: Path) -> None:
        rel = path.relative_to(root).as_posix()
        if len(analysis.parse_results) >= config.MAX_SOURCE_FILES:
            analysis.skipped.append({"file": rel, "reason": f"file limit ({config.MAX_SOURCE_FILES}) reached"})
            return
        if deadline is not None and time.monotonic() > deadline:
            analysis.skipped.append({"file": rel, "reason": "scan time limit reached"})
            return
        if path.stat().st_size > config.MAX_SOURCE_FILE_BYTES:
            analysis.skipped.append({"file": rel, "reason": "file larger than the size limit"})
            return
        result = parser.parse(path)
        analysis.parse_results.append(result)
        extractor.extract(result)
        result.tu = None            # release libclang memory as soon as features are extracted

    for unit in units:
        run(unit)
    for header in headers:
        rel = header.relative_to(root).as_posix()
        if rel not in extractor.features.files:
            run(header)

    for result in analysis.parse_results:
        if result.status == "failed":
            analysis.issues.append(ScanIssue("parser", result.message or "parse failed", file=result.file))
        elif result.status == "parsed_with_errors":
            first = result.diagnostics[0] if result.diagnostics else None
            analysis.issues.append(ScanIssue(
                "parser", f"{result.error_count} Clang error(s); analysis of this file may be incomplete"
                + (f" (first: {first.message})" if first else ""),
                level="WARNING", file=result.file, line=first.line if first else None,
                details={"stubbed_headers": result.stubbed_headers}))
        elif result.stubbed_headers:
            analysis.issues.append(ScanIssue(
                "parser", f"Header(s) not available, replaced by empty stubs: {', '.join(result.stubbed_headers)}",
                level="WARNING", file=result.file, details={"stubbed_headers": result.stubbed_headers}))
    if analysis.skipped:
        analysis.issues.append(ScanIssue("parser", f"{len(analysis.skipped)} source file(s) were not analysed.",
                                         level="WARNING", details={"skipped": analysis.skipped[:50]}))
    if not units:
        analysis.issues.append(ScanIssue("parser", "No C/C++ translation units found in src/, lib/ or .pio/libdeps.",
                                         level="WARNING"))
    return analysis
