import io

import pytest

from backend.project_loader import (ProjectError, locate_project_root, safe_extract, save_upload,
                                    validate_project)
from tests.helpers import make_zip

INI = "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n"


def _zip_file(tmp_path, files, **kwargs):
    path = tmp_path / "in.zip"
    path.write_bytes(make_zip(files, **kwargs))
    return path


def test_extracts_normal_project(tmp_path):
    archive = _zip_file(tmp_path, {"proj/platformio.ini": INI, "proj/src/main.cpp": "void setup(){}"})
    dest = tmp_path / "out"
    dest.mkdir()
    report = safe_extract(archive, dest)
    assert report.extracted_files == 2 and not report.skipped
    root = locate_project_root(dest)
    assert root.name == "proj"
    info = validate_project(root)
    assert info.has_src and info.source_file_count == 1


@pytest.mark.parametrize("bad_name", ["../evil.txt", "proj/../../evil.txt", "/etc/passwd",
                                      "C:/Windows/evil.txt", "proj/con.txt"])
def test_refuses_unsafe_paths(tmp_path, bad_name):
    archive = _zip_file(tmp_path, {"proj/platformio.ini": INI, bad_name: "x"})
    dest = tmp_path / "out"
    dest.mkdir()
    report = safe_extract(archive, dest)
    assert [s["path"] for s in report.skipped] == [bad_name]
    assert not (tmp_path / "evil.txt").exists()
    assert all(p.resolve().is_relative_to(dest.resolve()) for p in dest.rglob("*"))


def test_refuses_symlinks(tmp_path):
    archive = _zip_file(tmp_path, {"proj/platformio.ini": INI}, symlinks={"proj/link": "/etc/passwd"})
    dest = tmp_path / "out"
    dest.mkdir()
    report = safe_extract(archive, dest)
    assert report.skipped == [{"path": "proj/link", "reason": "symbolic link"}]


def test_enforces_uncompressed_size_limit(tmp_path):
    archive = _zip_file(tmp_path, {"proj/platformio.ini": INI, "proj/big.bin": b"0" * 50_000})
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(ProjectError, match="limit"):
        safe_extract(archive, dest, max_total=10_000)


def test_enforces_entry_limit(tmp_path):
    archive = _zip_file(tmp_path, {f"proj/f{i}.txt": "x" for i in range(20)})
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(ProjectError, match="entries"):
        safe_extract(archive, dest, max_entries=10)


def test_upload_must_be_zip(tmp_path):
    with pytest.raises(ProjectError, match=".zip"):
        save_upload(io.BytesIO(b"hello"), "project.tar", tmp_path)
    with pytest.raises(ProjectError, match="not a ZIP"):
        save_upload(io.BytesIO(b"not really a zip"), "project.zip", tmp_path)


def test_upload_size_limit(tmp_path):
    with pytest.raises(ProjectError, match="limit"):
        save_upload(io.BytesIO(b"PK\x03\x04" + b"0" * 5000), "p.zip", tmp_path, max_bytes=1000)


def test_missing_platformio_ini(tmp_path):
    archive = _zip_file(tmp_path, {"proj/src/main.cpp": "int x;"})
    dest = tmp_path / "out"
    dest.mkdir()
    safe_extract(archive, dest)
    with pytest.raises(ProjectError, match="platformio.ini"):
        locate_project_root(dest)


def test_corrupt_zip(tmp_path):
    path = tmp_path / "bad.zip"
    path.write_bytes(b"PK\x03\x04garbage")
    with pytest.raises(ProjectError):
        safe_extract(path, tmp_path)
