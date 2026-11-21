"""Load the trained Random Forest and predict GREEN/YELLOW/RED from ShipSafe-extracted features.

Any problem (missing file, schema mismatch, inference error) returns status "unavailable"
with the reason; it never returns a guessed label.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from backend import config
from backend.ml.features import FEATURE_NAMES, extract_features

MODEL_PATH = config.ROOT / "models" / "shipsafe_model.joblib"
SCHEMA_PATH = config.ROOT / "models" / "feature_schema.json"
METRICS_PATH = config.ROOT / "models" / "metrics.json"
_lock = threading.Lock()
_cache: dict = {}


def _load():
    with _lock:
        if "model" not in _cache:
            import joblib
            schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            if schema["features"] != FEATURE_NAMES:
                raise RuntimeError("feature_schema.json does not match ShipSafe's feature extractor")
            _cache["model"] = joblib.load(MODEL_PATH)
            _cache["schema"] = schema
            try:
                metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
                _cache["metrics"] = {k: metrics[k] for k in ("validation", "accuracy", "macro_f1", "samples")}
            except (OSError, ValueError, KeyError):
                _cache["metrics"] = None
        return _cache["model"], _cache["schema"], _cache["metrics"]


def ml_status() -> dict:
    try:
        _, schema, metrics = _load()
        return {"available": True, "model": schema["model"], "features": len(schema["features"]),
                "validation": metrics}
    except Exception as error:  # noqa: BLE001
        return {"available": False, "reason": f"{type(error).__name__}: {error}"}


def predict_project(root: Path, package_results: list[dict]) -> dict:
    try:
        model, schema, metrics = _load()
    except Exception as error:  # noqa: BLE001
        return {"status": "unavailable", "label": None, "reason": f"Model could not be loaded: {error}"}
    try:
        features, notes = extract_features(root, package_results)
        vector = [[float(features[name]) for name in schema["features"]]]
        probabilities = model.predict_proba(vector)[0]
        classes = [str(c) for c in model.classes_]
        label = classes[int(probabilities.argmax())]
        return {"status": "ok", "label": label,
                "probabilities": {c: round(float(p), 3) for c, p in zip(classes, probabilities)},
                "features": features, "notes": notes, "model": schema["model"],
                "validation": metrics,
                "statement": "Random Forest trained on 100 synthetic, synthetically labelled ESP32 projects. "
                             "It is an additional signal, never an override of the security engine."}
    except Exception as error:  # noqa: BLE001
        return {"status": "unavailable", "label": None, "reason": f"Inference failed: {type(error).__name__}: {error}"}
