"""ShipSafe HTTP API.

    uvicorn backend.main:app --port 8000

POST /api/scan            multipart: file=<project.zip>, chip=<profile id or empty for auto>,
                          registry=online|offline (offline = cached registry answers only)
POST /api/scan/demo       scans the bundled, clearly labelled demo project
GET  /api/scan/{scan_id}  status (+ full report when completed)
GET  /api/profiles        chip profiles the hardware checker knows
GET  /api/health          health information
"""

from __future__ import annotations

import io
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend import config, scan_service
from backend.project_loader import ProjectError, cleanup, new_work_dir, save_upload

app = FastAPI(title="ShipSafe", version="2.0.0",
              description="Explainable, hardware-aware security analysis for ESP32 PlatformIO projects")
app.state.store = scan_service.ScanStore()
app.state.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan")
app.state.scan_options = {}       # tests inject e.g. a mocked registry client here

DEMO_PROJECT = config.SAMPLES / "demo_project"


def _submit(zip_path: Path, work_dir: Path, chip: str | None, name: str, registry: str,
            demo: bool = False) -> dict:
    if registry not in ("online", "offline"):
        cleanup(work_dir)
        raise HTTPException(status_code=400, detail="registry must be 'online' or 'offline'")
    record = app.state.store.create()
    options = {"registry_offline": registry == "offline", **app.state.scan_options}
    app.state.executor.submit(scan_service.run_scan_job, record, zip_path, work_dir,
                              chip=chip or None, project_name=name, demo=demo, **options)
    return {"scan_id": record.scan_id, "status": record.status}


@app.post("/api/scan", status_code=202)
def create_scan(file: UploadFile = File(...), chip: str = Form(""), registry: str = Form("online")) -> dict:
    work_dir = new_work_dir()
    try:
        zip_path = save_upload(file.file, file.filename or "", work_dir)
    except ProjectError as error:
        cleanup(work_dir)
        raise HTTPException(status_code=400, detail=str(error)) from error
    name = Path(file.filename or "project.zip").stem
    return _submit(zip_path, work_dir, chip, name, registry)


@app.post("/api/scan/demo", status_code=202)
def create_demo_scan(chip: str = Form(""), registry: str = Form("online")) -> dict:
    if not (DEMO_PROJECT / "platformio.ini").is_file():
        raise HTTPException(status_code=404, detail="Demo project is not installed.")
    work_dir = new_work_dir()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in DEMO_PROJECT.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(DEMO_PROJECT.parent).as_posix())
    zip_path = work_dir / "upload.zip"
    zip_path.write_bytes(buffer.getvalue())
    return _submit(zip_path, work_dir, chip, "demo_project (DEMO)", registry, demo=True)


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str) -> JSONResponse:
    record = app.state.store.get(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown scan id (scans are kept in memory only).")
    return JSONResponse(record.to_dict())


@app.get("/api/profiles")
def profiles() -> dict:
    return scan_service.available_profiles()


@app.get("/api/health")
def health() -> dict:
    return scan_service.health_info()


if config.FRONTEND.is_dir():
    app.mount("/", StaticFiles(directory=config.FRONTEND, html=True), name="frontend")
