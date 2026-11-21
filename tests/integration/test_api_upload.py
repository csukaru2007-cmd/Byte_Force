from tests.helpers import make_zip

INI = ("[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n"
       "lib_deps = bblanchon/ArduinoJson@7.4.3\n")


def test_health(api_client):
    client, _ = api_client
    response = client.get("/api/health")
    assert response.status_code == 200 and response.json()["status"] == "ok"


def test_upload_extracts_dependencies_and_cleans_up(api_client, tmp_path):
    client, _ = api_client
    archive = make_zip({"MyProj/platformio.ini": INI, "MyProj/src/main.cpp": "void setup(){}\nvoid loop(){}\n"})
    response = client.post("/api/scan", files={"file": ("MyProj.zip", archive, "application/zip")})
    assert response.status_code == 202
    scan = client.get(f"/api/scan/{response.json()['scan_id']}").json()
    assert scan["status"] == "completed", scan
    names = [r["dependency"]["name"] for r in scan["package_results"]]
    assert "ArduinoJson" in names
    # the per-scan work folder is removed after the scan
    assert list((tmp_path / "scans").iterdir()) == []


def test_rejects_non_zip(api_client):
    client, _ = api_client
    response = client.post("/api/scan", files={"file": ("x.txt", b"hello", "text/plain")})
    assert response.status_code == 400


def test_not_a_platformio_project_fails_cleanly(api_client):
    client, _ = api_client
    response = client.post("/api/scan", files={"file": ("p.zip", make_zip({"a/readme.md": "hi"}), "application/zip")})
    scan = client.get(f"/api/scan/{response.json()['scan_id']}").json()
    assert scan["status"] == "failed" and "platformio.ini" in scan["error"]


def test_unknown_scan_id(api_client):
    client, _ = api_client
    assert client.get("/api/scan/doesnotexist").status_code == 404
