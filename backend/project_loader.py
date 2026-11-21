"""Safe handling of uploaded PlatformIO project archives.

Nothing in here executes project content. The archive is only read and copied:

* only .zip uploads are accepted (extension and magic bytes are checked)
* upload size, number of entries, total uncompressed size and compression ratio are limited
* absolute paths, drive letters, ``..`` components, symlinks and encrypted entries are refused
* every extracted path is resolved and must stay inside the scan's own temporary folder
* the bytes written are counted while copying, so a lying ZIP header cannot exceed the limit
"""

from __future__ import annotations

import re
import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from backend import config

ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", re.IGNORECASE)
_INVALID_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".ino", ".h", ".hh", ".hpp", ".hxx"}


class ProjectError(Exception):
    """The upload cannot be analysed (not a ZIP, unsafe archive, not a PlatformIO project...)."""


@dataclass
class ExtractionReport:
    extracted_files: int = 0
    extracted_bytes: int = 0
    skipped: list[dict] = field(default_factory=list)   # {"path":..., "reason":...}


@dataclass
class ProjectInfo:
    name: str
    root: Path                     # folder containing platformio.ini
    ini_path: Path
    has_src: bool
    has_include: bool
    has_lib: bool
    has_installed_libdeps: bool    # .pio/libdeps present in the archive
    source_file_count: int
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name, "has_src": self.has_src, "has_include": self.has_include,
            "has_lib": self.has_lib, "has_installed_libdeps": self.has_installed_libdeps,
            "source_file_count": self.source_file_count, "warnings": self.warnings,
        }


def new_work_dir() -> Path:
    config.SCAN_WORK_DIR.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="scan_", dir=config.SCAN_WORK_DIR))


def cleanup(path: Path | None) -> None:
    if path and path.exists():
        shutil.rmtree(path, ignore_errors=True)


def save_upload(stream: BinaryIO, filename: str, dest_dir: Path,
                max_bytes: int | None = None) -> Path:
    """Copy an uploaded file to disk, enforcing the size limit and the ZIP type."""
    max_bytes = max_bytes or config.MAX_UPLOAD_BYTES
    if not filename or not filename.lower().endswith(".zip"):
        raise ProjectError("Only .zip archives of a PlatformIO project are accepted.")
    target = dest_dir / "upload.zip"
    written = 0
    with open(target, "wb") as out:
        while chunk := stream.read(1024 * 1024):
            written += len(chunk)
            if written > max_bytes:
                raise ProjectError(f"Upload exceeds the {max_bytes // (1024 * 1024)} MB limit.")
            out.write(chunk)
    with open(target, "rb") as check:
        if check.read(4) not in ZIP_MAGIC:
            raise ProjectError("The uploaded file is not a ZIP archive.")
    return target


def _unsafe_reason(name: str) -> str | None:
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or re.match(r"^[A-Za-z]:", normalised):
        return "absolute path"
    parts = PurePosixPath(normalised).parts
    if any(part == ".." for part in parts):
        return "path traversal (..)"
    for part in parts:
        if _WINDOWS_RESERVED.match(part) or _INVALID_CHARS.search(part):
            return "invalid file name on Windows"
    return None


def safe_extract(zip_path: Path, dest: Path, *, max_total: int | None = None,
                 max_entries: int | None = None, max_ratio: int | None = None) -> ExtractionReport:
    max_total = max_total or config.MAX_UNCOMPRESSED_BYTES
    max_entries = max_entries or config.MAX_ARCHIVE_ENTRIES
    max_ratio = max_ratio or config.MAX_COMPRESSION_RATIO
    report = ExtractionReport()
    dest_resolved = dest.resolve()
    try:
        archive = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as error:
        raise ProjectError(f"The archive is corrupt or not a ZIP file: {error}") from error

    with archive:
        entries = archive.infolist()
        if len(entries) > max_entries:
            raise ProjectError(f"Archive has {len(entries)} entries; the limit is {max_entries}.")
        declared_total = sum(info.file_size for info in entries)
        if declared_total > max_total:
            raise ProjectError(f"Archive expands to {declared_total} bytes; the limit is {max_total}.")

        for info in entries:
            name = info.filename
            if name.startswith("__MACOSX/") or info.is_dir():
                continue
            reason = _unsafe_reason(name)
            mode = info.external_attr >> 16
            if reason is None and stat.S_ISLNK(mode):
                reason = "symbolic link"
            if reason is None and info.flag_bits & 0x1:
                reason = "encrypted entry"
            if reason is None and info.file_size > 1024 * 1024 and \
                    info.file_size / max(info.compress_size, 1) > max_ratio:
                reason = "suspicious compression ratio"
            if reason:
                report.skipped.append({"path": name, "reason": reason})
                continue

            target = (dest / name.replace("\\", "/")).resolve()
            if not target.is_relative_to(dest_resolved):
                report.skipped.append({"path": name, "reason": "resolves outside the scan folder"})
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, open(target, "wb") as out:
                while chunk := source.read(1024 * 256):
                    report.extracted_bytes += len(chunk)
                    if report.extracted_bytes > max_total:
                        raise ProjectError("Archive content exceeds the uncompressed size limit.")
                    out.write(chunk)
            report.extracted_files += 1
    return report


def locate_project_root(extracted: Path) -> Path:
    """Return the shallowest folder that contains platformio.ini."""
    candidates = [p for p in extracted.rglob("platformio.ini")
                  if ".pio" not in p.relative_to(extracted).parts and p.is_file()]
    if not candidates:
        raise ProjectError("No platformio.ini found. Upload the root folder of a PlatformIO project.")
    candidates.sort(key=lambda p: (len(p.relative_to(extracted).parts), str(p)))
    return candidates[0].parent


def validate_project(root: Path, display_name: str | None = None) -> ProjectInfo:
    ini = root / "platformio.ini"
    if not ini.is_file():
        raise ProjectError("platformio.ini is missing.")
    warnings = []
    has_src, has_include, has_lib = ((root / d).is_dir() for d in ("src", "include", "lib"))
    if not has_src:
        warnings.append("No src/ folder: the project has no application sources to analyse.")
    sources = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SOURCE_EXTENSIONS]
    if not sources:
        warnings.append("No C/C++ source files were found.")
    return ProjectInfo(
        name=display_name or root.name,
        root=root,
        ini_path=ini,
        has_src=has_src,
        has_include=has_include,
        has_lib=has_lib,
        has_installed_libdeps=(root / ".pio" / "libdeps").is_dir(),
        source_file_count=len(sources),
        warnings=warnings,
    )
