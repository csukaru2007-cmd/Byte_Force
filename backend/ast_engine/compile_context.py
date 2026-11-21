"""Compilation context for parsing PlatformIO / Arduino sources with Clang.

Clang needs include directories, macro definitions and a language standard. ShipSafe
never runs the PlatformIO build (that would execute project scripts), so the context
is assembled from data only:

1. compile_commands.json, if the upload contains one (PlatformIO writes it with
   `pio run -t compiledb`). -D/-I/-std/-include flags are kept; Xtensa/GCC-only
   flags are dropped. Include paths that do not exist on this machine are reported.
2. Otherwise: build_flags (-D/-I) from platformio.ini, the project's include/, src/,
   lib/ and .pio/libdeps folders, then ShipSafe's declaration-only stub headers for the
   Arduino-ESP32 / ESP-IDF APIs (backend/ast_engine/stubs), searched last so real
   headers in the upload always win.

Headers that still cannot be found are replaced by empty files (see clang_parser.py)
and listed in the report, so missing context is visible instead of silently dropped.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath

from backend.config import STUB_HEADERS
from backend.platformio.ini_parser import EnvironmentInfo

# Clang 18 has no Xtensa target in the libclang wheel; a 32-bit target keeps int/pointer
# sizes equal to the ESP32 (both 32 bit). Only syntax and types are needed, no codegen.
BASE_ARGS = ["-std=gnu++17", "--target=i686-unknown-linux-gnu", "-w", "-ferror-limit=0",
             "-fno-delayed-template-parsing"]
C_ARGS = ["-std=gnu11", "--target=i686-unknown-linux-gnu", "-w", "-ferror-limit=0"]
DEFAULT_DEFINES = {"ARDUINO": "10812", "ARDUINO_ARCH_ESP32": None, "ESP32": None,
                   "ESP_PLATFORM": None, "SHIPSAFE_ANALYSIS": None}
_KEEP_PREFIXES = ("-D", "-I", "-U", "-std=", "-include", "-isystem")


@dataclass
class CompileContext:
    mode: str                                   # "compile_commands" or "platformio_ini+stubs"
    include_dirs: list[Path]
    defines: dict[str, str | None]
    missing_header_dir: Path
    per_file_flags: dict[str, list[str]] = field(default_factory=dict)   # rel path -> flags
    notes: list[str] = field(default_factory=list)

    def args_for(self, path: Path, project_root: Path) -> list[str]:
        is_c = path.suffix.lower() == ".c"
        args = ["-x", "c" if is_c else "c++"] + (C_ARGS if is_c else BASE_ARGS)
        rel = path.relative_to(project_root).as_posix() if path.is_relative_to(project_root) else str(path)
        specific = self.per_file_flags.get(rel)
        if specific is not None:
            args += specific
        for name, value in self.defines.items():
            args.append(f"-D{name}" if value is None else f"-D{name}={value}")
        for directory in self.include_dirs:
            args.append(f"-I{directory}")
        args += [f"-I{STUB_HEADERS}", f"-I{self.missing_header_dir}"]
        if path.suffix.lower() == ".ino":
            args += ["-include", "Arduino.h"]
        return args

    def to_dict(self, project_root: Path) -> dict:
        def show(p: Path) -> str:
            return p.relative_to(project_root).as_posix() if p.is_relative_to(project_root) else str(p)
        return {"mode": self.mode, "include_dirs": [show(p) for p in self.include_dirs],
                "defines": self.defines, "stub_headers": "backend/ast_engine/stubs (searched last)",
                "files_with_compile_commands": len(self.per_file_flags), "notes": self.notes}


def _library_dirs(folder: Path) -> list[Path]:
    dirs = []
    if folder.is_dir():
        for lib in sorted(p for p in folder.iterdir() if p.is_dir()):
            dirs.append(lib)
            if (lib / "src").is_dir():
                dirs.append(lib / "src")
    return dirs


def _rebase(raw: str, root: Path, directory: str | None) -> Path | None:
    """Map an include path from another machine onto the extracted project, if possible."""
    candidate = Path(raw)
    if not candidate.is_absolute() and directory:
        candidate = Path(directory) / raw
    if candidate.exists():
        return candidate
    parts = (PureWindowsPath(raw) if "\\" in raw else PurePosixPath(raw)).parts
    for marker in ("src", "include", "lib", ".pio"):
        if marker in parts:
            index = len(parts) - 1 - parts[::-1].index(marker)
            mapped = root.joinpath(*parts[index:])
            if mapped.exists():
                return mapped
    return None


def _from_compile_commands(root: Path, path: Path, notes: list[str]) -> dict[str, list[str]]:
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        notes.append(f"compile_commands.json could not be read: {error}")
        return {}
    per_file: dict[str, list[str]] = {}
    dropped: set[str] = set()
    missing_includes: set[str] = set()
    for entry in entries if isinstance(entries, list) else []:
        args = entry.get("arguments") or shlex.split(entry.get("command", ""), posix=True)
        file_name = entry.get("file", "")
        target = _rebase(file_name, root, entry.get("directory"))
        if target is None or not target.is_relative_to(root):
            continue
        kept: list[str] = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-I", "-D", "-include", "-isystem") and i + 1 < len(args):
                arg, i = arg + ("" if arg in ("-I", "-D") else " ") + args[i + 1], i + 1
            if arg.startswith(("-I", "-isystem")):
                raw = arg[2:] if arg.startswith("-I") else arg.split(" ", 1)[1]
                mapped = _rebase(raw, root, entry.get("directory"))
                if mapped:
                    kept.append(f"-I{mapped}")
                else:
                    missing_includes.add(raw)
            elif arg.startswith("-include "):
                kept += ["-include", arg.split(" ", 1)[1]]
            elif arg.startswith(_KEEP_PREFIXES) and not arg.startswith("-std=gnu++2b"):
                kept.append(arg)
            elif arg.startswith("-"):
                dropped.add(arg)
            i += 1
        per_file[target.relative_to(root).as_posix()] = kept
    notes.append(f"compile_commands.json: flags for {len(per_file)} file(s) used.")
    if dropped:
        notes.append(f"{len(dropped)} compiler flag(s) not supported by the analysis target were dropped "
                     f"(e.g. {', '.join(sorted(dropped)[:5])}).")
    if missing_includes:
        notes.append(f"{len(missing_includes)} include path(s) from compile_commands.json do not exist on this "
                     "machine (e.g. framework packages); ShipSafe stub headers are used instead.")
    return per_file


def build_context(root: Path, env: EnvironmentInfo | None, work_dir: Path) -> CompileContext:
    notes: list[str] = []
    missing_dir = work_dir / "missing_headers"
    missing_dir.mkdir(parents=True, exist_ok=True)

    defines = dict(DEFAULT_DEFINES)
    include_dirs: list[Path] = []
    for name in ("include", "src"):
        if (root / name).is_dir():
            include_dirs.append(root / name)
    include_dirs += _library_dirs(root / "lib")
    libdeps = root / ".pio" / "libdeps"
    if libdeps.is_dir():
        env_dirs = [libdeps / env.name] if env and (libdeps / env.name).is_dir() else \
            sorted(p for p in libdeps.iterdir() if p.is_dir())
        for env_dir in env_dirs:
            include_dirs += _library_dirs(env_dir)
    if env:
        defines.update(env.defines)
        for raw in env.include_dirs:
            candidate = (root / raw).resolve()
            if candidate.is_dir() and candidate.is_relative_to(root.resolve()):
                include_dirs.append(candidate)
            else:
                notes.append(f"build_flags include path '{raw}' is outside the project or missing; ignored.")

    per_file: dict[str, list[str]] = {}
    mode = "platformio_ini+stubs"
    for candidate in (root / "compile_commands.json", *sorted((root / ".pio" / "build").glob("*/compile_commands.json"))):
        if candidate.is_file():
            per_file = _from_compile_commands(root, candidate, notes)
            if per_file:
                mode = "compile_commands"
            break
    if mode != "compile_commands":
        notes.append("No usable compile_commands.json: using platformio.ini build_flags, project/library include "
                     "folders and ShipSafe's declaration-only Arduino-ESP32/ESP-IDF stub headers.")
    return CompileContext(mode=mode, include_dirs=include_dirs, defines=defines,
                          missing_header_dir=missing_dir, per_file_flags=per_file, notes=notes)
