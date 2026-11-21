"""Parse C/C++ files into Clang ASTs (libclang Python bindings, Clang 18).

Parsing only: nothing from the project is compiled to machine code or executed.

Missing headers: when Clang reports "'X.h' file not found" it stops reporting further
diagnostics for that file. ShipSafe therefore writes an empty X.h into a per-scan
folder, records it, and parses again, so that the rest of the file is analysed and its
remaining errors (e.g. unknown types from the missing library) are reported too.
"""

from __future__ import annotations

import ctypes
import re
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from backend.ast_engine.compile_context import CompileContext

try:
    import clang.cindex as cindex
except ImportError:  # pragma: no cover - reported by clang_status()
    cindex = None

MAX_STUB_ROUNDS = 25
MAX_DIAGNOSTICS_PER_FILE = 40
_NOT_FOUND = re.compile(r"^'(.+)' file not found")


@dataclass
class Diagnostic:
    severity: str          # "error" | "fatal"
    message: str
    file: str | None
    line: int | None

    def to_dict(self) -> dict:
        return {"severity": self.severity, "message": self.message, "file": self.file, "line": self.line}


@dataclass
class ParseResult:
    file: str                                   # path relative to project root
    status: str                                 # parsed | parsed_with_errors | failed | skipped
    diagnostics: list[Diagnostic] = field(default_factory=list)
    stubbed_headers: list[str] = field(default_factory=list)
    error_count: int = 0
    seconds: float = 0.0
    message: str | None = None
    tu: object | None = None                    # clang.cindex.TranslationUnit (not serialised)

    def to_dict(self) -> dict:
        return {"file": self.file, "status": self.status, "error_count": self.error_count,
                "diagnostics": [d.to_dict() for d in self.diagnostics],
                "stubbed_headers": self.stubbed_headers, "seconds": round(self.seconds, 3),
                "message": self.message}


_eval_ready = False


def _register_evaluate() -> None:
    """Expose clang_Cursor_Evaluate (constant folding), which cindex 18 does not wrap."""
    global _eval_ready
    if _eval_ready or cindex is None:
        return
    lib = cindex.conf.lib
    lib.clang_Cursor_Evaluate.argtypes = [cindex.Cursor]
    lib.clang_Cursor_Evaluate.restype = ctypes.c_void_p
    lib.clang_EvalResult_getKind.argtypes = [ctypes.c_void_p]
    lib.clang_EvalResult_getKind.restype = ctypes.c_int
    lib.clang_EvalResult_getAsLongLong.argtypes = [ctypes.c_void_p]
    lib.clang_EvalResult_getAsLongLong.restype = ctypes.c_longlong
    lib.clang_EvalResult_getAsDouble.argtypes = [ctypes.c_void_p]
    lib.clang_EvalResult_getAsDouble.restype = ctypes.c_double
    lib.clang_EvalResult_getAsStr.argtypes = [ctypes.c_void_p]
    lib.clang_EvalResult_getAsStr.restype = ctypes.c_char_p
    lib.clang_EvalResult_dispose.argtypes = [ctypes.c_void_p]
    lib.clang_EvalResult_dispose.restype = None
    _eval_ready = True


def evaluate(cursor) -> int | float | str | None:
    """Constant-fold an expression cursor with Clang. None when it is not a constant."""
    _register_evaluate()
    lib = cindex.conf.lib
    try:
        handle = lib.clang_Cursor_Evaluate(cursor)
    except Exception:  # noqa: BLE001 - libclang can reject some cursors
        return None
    if not handle:
        return None
    try:
        kind = lib.clang_EvalResult_getKind(handle)
        if kind == 1:        # CXEval_Int
            return int(lib.clang_EvalResult_getAsLongLong(handle))
        if kind == 2:        # CXEval_Float
            return float(lib.clang_EvalResult_getAsDouble(handle))
        if kind == 4:        # CXEval_StrLiteral
            raw = lib.clang_EvalResult_getAsStr(handle)
            return raw.decode("utf-8", "replace") if raw is not None else None
        return None
    finally:
        lib.clang_EvalResult_dispose(handle)


def clang_status() -> dict:
    if cindex is None:
        return {"available": False, "error": "python package 'libclang' is not installed"}
    try:
        from importlib.metadata import PackageNotFoundError, version

        cindex.Index.create()
        # clang_getClangVersion is not wrapped by cindex 18 (calling it raw corrupts memory),
        # so report the version of the installed libclang package instead.
        try:
            libclang_version = version("libclang")
        except PackageNotFoundError:
            libclang_version = "unknown"
        return {"available": True, "version": f"libclang {libclang_version}", "library": cindex.conf.lib._name}
    except Exception as error:  # noqa: BLE001
        return {"available": False, "error": f"{type(error).__name__}: {error}"}


class ClangParser:
    def __init__(self, context: CompileContext, project_root: Path):
        if cindex is None:
            raise RuntimeError("libclang is not installed")
        self.context = context
        self.root = project_root
        self.index = cindex.Index.create()
        self.options = cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD

    def _rel(self, path: str | None) -> str | None:
        if not path:
            return None
        p = Path(path)
        try:
            return p.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            if p.is_relative_to(self.context.missing_header_dir):
                return f"<missing header stub>/{p.relative_to(self.context.missing_header_dir).as_posix()}"
            return f"<external>/{p.name}"

    def _stub_header(self, name: str) -> bool:
        posix = PurePosixPath(name.replace("\\", "/"))
        if posix.is_absolute() or ".." in posix.parts or not posix.parts:
            return False
        target = self.context.missing_header_dir.joinpath(*posix.parts)
        if target.exists():
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("// empty stub generated by ShipSafe: header not available\n#pragma once\n",
                          encoding="utf-8")
        return True

    def parse(self, path: Path) -> ParseResult:
        rel = self._rel(str(path)) or path.name
        started = time.monotonic()
        args = self.context.args_for(path, self.root)
        stubbed: list[str] = []
        tu = None
        for _ in range(MAX_STUB_ROUNDS):
            try:
                tu = self.index.parse(str(path), args=args, options=self.options)
            except cindex.TranslationUnitLoadError as error:
                return ParseResult(rel, "failed", message=f"Clang could not parse the file: {error}",
                                   stubbed_headers=stubbed, seconds=time.monotonic() - started)
            missing = None
            for diag in tu.diagnostics:
                match = _NOT_FOUND.match(diag.spelling)
                if diag.severity >= cindex.Diagnostic.Fatal and match:
                    missing = match.group(1)
                    break
            if missing is None:
                break
            if not self._stub_header(missing):
                break               # cannot stub (unsafe path or already stubbed): keep the fatal error
            stubbed.append(missing)

        diagnostics: list[Diagnostic] = []
        error_count = 0
        for diag in tu.diagnostics:
            if diag.severity < cindex.Diagnostic.Error:
                continue
            error_count += 1
            if len(diagnostics) < MAX_DIAGNOSTICS_PER_FILE:
                location = diag.location
                diagnostics.append(Diagnostic(
                    "fatal" if diag.severity >= cindex.Diagnostic.Fatal else "error", diag.spelling,
                    self._rel(location.file.name) if location.file else None,
                    location.line if location.file else None))
        status = "parsed" if error_count == 0 else "parsed_with_errors"
        return ParseResult(rel, status, diagnostics, stubbed, error_count,
                           time.monotonic() - started, tu=tu)
