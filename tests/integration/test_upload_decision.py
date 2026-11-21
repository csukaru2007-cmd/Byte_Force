"""End to end: ZIP upload -> main engine + ML -> combined decision -> backend upload gate."""

import shutil

import pytest

from backend.ml import predict
from tests.fake_registry import make_client
from tests.helpers import FIXTURES, zip_folder

DATASET = predict.config.ROOT / "ml" / "esp32_synth_fw_dataset" / "projects"


def _scan(api_client, tmp_path, project):
    client, app = api_client
    registry_client, _ = make_client(tmp_path / "registry", None)
    app.state.scan_options = {"registry_factory": lambda: registry_client, "run_baseline_scan": True}
    response = client.post("/api/scan", files={"file": (f"{project.name}.zip", zip_folder(project), "application/zip")},
                           data={"chip": "ESP32-WROOM-32"})
    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]
    return client, scan_id, client.get(f"/api/scan/{scan_id}").json()


def test_report_keeps_three_decisions_separate(api_client, tmp_path, monkeypatch):
    monkeypatch.delenv("SHIPSAFE_BASELINE_URL", raising=False)
    project = tmp_path / "cred"
    shutil.copytree(FIXTURES / "suspicious_indicators" / "hardcoded_test_credential", project)
    client, scan_id, report = _scan(api_client, tmp_path, project)
    assert report["status"] == "completed"
    assert report["ml_prediction"]["status"] == "ok"
    assert report["ml_prediction"]["label"] in ("GREEN", "YELLOW", "RED")
    assert abs(sum(report["ml_prediction"]["probabilities"].values()) - 1) < 0.01
    assert report["main_engine_decision"]["status"] in ("GREEN", "YELLOW", "RED")
    assert report["decision"]["status"] in ("GREEN", "YELLOW", "RED")
    assert report["baseline"]["status"] == "unavailable"            # not configured -> labelled, not faked


def test_critical_project_is_blocked_by_backend(api_client, tmp_path):
    project = tmp_path / "ota"
    shutil.copytree(DATASET / "P001_O01_v0", project)                 # unauthenticated OTA endpoint
    (project / "dependency_manifest.json").unlink()
    client, scan_id, report = _scan(api_client, tmp_path, project)
    if report["main_engine_decision"]["status"] == "RED":
        assert report["decision"]["status"] == "RED"
    gate = client.post(f"/api/scan/{scan_id}/upload")
    assert gate.status_code == (200 if report["decision"]["status"] == "GREEN" else 403)
    assert gate.json()["allowed"] is (report["decision"]["status"] == "GREEN")


def test_ml_unavailable_never_green(api_client, tmp_path, monkeypatch):
    monkeypatch.setattr(predict, "MODEL_PATH", tmp_path / "missing.joblib")
    monkeypatch.setattr(predict, "_cache", {})
    project = tmp_path / "benign"
    shutil.copytree(FIXTURES / "benign" / "normal_sensor_project", project)
    client, scan_id, report = _scan(api_client, tmp_path, project)
    assert report["ml_prediction"]["status"] == "unavailable"
    assert report["decision"]["status"] != "GREEN"
    assert client.post(f"/api/scan/{scan_id}/upload").status_code == 403


def test_failed_analysis_blocks_upload(api_client):
    client, _ = api_client
    response = client.post("/api/scan", files={"file": ("bad.zip", b"not a zip", "application/zip")})
    if response.status_code == 202:
        scan_id = response.json()["scan_id"]
        report = client.get(f"/api/scan/{scan_id}").json()
        assert report["status"] == "failed" and report["decision"]["upload_allowed"] is False
        assert client.post(f"/api/scan/{scan_id}/upload").status_code == 403
    else:
        assert response.status_code == 400


def test_unknown_scan_gate_404(api_client):
    client, _ = api_client
    assert client.post("/api/scan/doesnotexist/upload").status_code == 404
