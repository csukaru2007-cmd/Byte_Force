import pytest


class ImmediateExecutor:
    """Runs submitted scans synchronously so API tests are deterministic."""

    def submit(self, fn, *args, **kwargs):
        fn(*args, **kwargs)


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from backend import config
    from backend.main import app

    monkeypatch.setattr(config, "SCAN_WORK_DIR", tmp_path / "scans")
    original_executor, original_options = app.state.executor, app.state.scan_options
    app.state.executor = ImmediateExecutor()
    # never contact the real registry from automated tests unless a test injects a fake client
    app.state.scan_options = {"registry_offline": True}
    try:
        yield TestClient(app), app
    finally:
        app.state.executor, app.state.scan_options = original_executor, original_options
