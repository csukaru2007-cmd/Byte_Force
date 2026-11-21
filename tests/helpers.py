"""Shared test helpers."""

from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def make_zip(files: dict[str, str | bytes], *, symlinks: dict[str, str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o120777 << 16)
            archive.writestr(info, target)
    return buffer.getvalue()


def zip_folder(folder: Path, prefix: str | None = None) -> bytes:
    prefix = prefix if prefix is not None else folder.name
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                rel = path.relative_to(folder).as_posix()
                archive.write(path, f"{prefix}/{rel}" if prefix else rel)
    return buffer.getvalue()


def write_project(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def copy_fixture(name: str, dest: Path) -> Path:
    target = dest / Path(name).name
    shutil.copytree(FIXTURES / name, target)
    return target


def line_of(root: Path, rel: str, needle: str) -> int:
    for number, line in enumerate((root / rel).read_text(encoding="utf-8").splitlines(), 1):
        if needle in line:
            return number
    raise AssertionError(f"{needle!r} not found in {rel}")


def analyse_fixture(name: str, tmp_path: Path):
    """Copy a fixture, extract dependencies and run the Clang AST analysis on it."""
    from backend.ast_engine.runner import analyse_sources
    from backend.platformio.ini_parser import extract_dependencies

    root = copy_fixture(name, tmp_path)
    extraction = extract_dependencies(root)
    env = extraction.environments[0] if extraction.environments else None
    analysis = analyse_sources(root, env, tmp_path / "work")
    return root, extraction, analysis
