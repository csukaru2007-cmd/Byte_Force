"""Train the ShipSafe Random Forest on the synthetic ESP32 firmware dataset.

    python -m scripts.train_model

Writes models/shipsafe_model.joblib, models/feature_schema.json and models/metrics.json.
Validation is grouped by scenario_id (GroupKFold), so variants of one scenario never appear
in both the training and the validation fold.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import GroupKFold

from backend.ml.features import FEATURE_NAMES, dependency_features, project_text, source_features

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "ml" / "esp32_synth_fw_dataset"
OUT = ROOT / "models"
LABELS = ["GREEN", "YELLOW", "RED"]
PARAMS = dict(n_estimators=300, max_depth=None, min_samples_leaf=1, class_weight="balanced", random_state=42)


def load():
    rows = list(csv.DictReader((DATASET / "labels.csv").open(encoding="utf-8")))
    columns = [c for c in rows[0] if c.startswith(("f_", "d_"))]
    assert columns == FEATURE_NAMES, f"dataset columns differ from ShipSafe schema: {columns}"
    X = np.array([[float(r[c]) for c in columns] for r in rows])
    y = np.array([r["label"] for r in rows])
    groups = np.array([r["scenario_id"] for r in rows])
    return rows, X, y, groups


def extractor_agreement(rows) -> dict:
    """Check that ShipSafe's own f_* extraction reproduces the dataset's f_* columns."""
    mismatches = []
    for r in rows:
        project = DATASET / "projects" / r["project_id"]
        mine = source_features(project_text(project))
        manifest = json.loads((project / "dependency_manifest.json").read_text(encoding="utf-8"))
        mine.update(dependency_features(manifest))
        diff = [k for k in FEATURE_NAMES if float(mine[k]) != float(r[k])]
        if diff:
            mismatches.append({"project_id": r["project_id"], "features": diff})
    return {"projects": len(rows), "projects_with_mismatch": len(mismatches), "mismatches": mismatches[:20]}


def main() -> None:
    rows, X, y, groups = load()
    n_groups = len(set(groups))
    cv = GroupKFold(n_splits=5)
    predictions = np.empty(len(y), dtype=object)
    for train_idx, test_idx in cv.split(X, y, groups):
        model = RandomForestClassifier(**PARAMS).fit(X[train_idx], y[train_idx])
        predictions[test_idx] = model.predict(X[test_idx])
    predictions = predictions.astype(str)

    precision, recall, f1, support = precision_recall_fscore_support(y, predictions, labels=LABELS, zero_division=0)
    macro = precision_recall_fscore_support(y, predictions, labels=LABELS, average="macro", zero_division=0)
    metrics = {
        "validation": "GroupKFold(n_splits=5) grouped by scenario_id (out-of-fold predictions for all rows)",
        "samples": len(y), "scenarios": n_groups,
        "class_counts": {label: int((y == label).sum()) for label in LABELS},
        "accuracy": round(float(accuracy_score(y, predictions)), 4),
        "macro_precision": round(float(macro[0]), 4), "macro_recall": round(float(macro[1]), 4),
        "macro_f1": round(float(macro[2]), 4),
        "per_class": {label: {"precision": round(float(p), 4), "recall": round(float(r), 4),
                              "f1": round(float(f), 4), "support": int(s)}
                      for label, p, r, f, s in zip(LABELS, precision, recall, f1, support)},
        "confusion_matrix": {"labels": LABELS, "rows_true_cols_pred":
                             confusion_matrix(y, predictions, labels=LABELS).tolist()},
        "report": classification_report(y, predictions, labels=LABELS, zero_division=0),
    }

    final = RandomForestClassifier(**PARAMS).fit(X, y)
    OUT.mkdir(exist_ok=True)
    joblib.dump(final, OUT / "shipsafe_model.joblib")
    schema = {"features": FEATURE_NAMES, "classes": [str(c) for c in final.classes_],
              "model": "RandomForestClassifier", "params": PARAMS, "sklearn_version": sklearn.__version__,
              "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "dataset": "ml/esp32_synth_fw_dataset (100 synthetic projects, synthetic labels)",
              "excluded_columns": ["project_id", "scenario_id", "category", "scenario", "label", "label_id",
                                   "variant", "language", "split", "edge_case", "n_files", "rationale", "loc"]}
    (OUT / "feature_schema.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")
    metrics["extractor_agreement"] = extractor_agreement(rows)
    metrics["feature_importances"] = dict(sorted(
        ((n, round(float(v), 4)) for n, v in zip(FEATURE_NAMES, final.feature_importances_)),
        key=lambda kv: -kv[1]))
    (OUT / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(metrics["report"])
    print("confusion (rows=true, cols=pred)", LABELS, metrics["confusion_matrix"]["rows_true_cols_pred"])
    print("accuracy", metrics["accuracy"], "macro F1", metrics["macro_f1"])
    print("extractor agreement:", {k: v for k, v in metrics["extractor_agreement"].items() if k != "mismatches"})


if __name__ == "__main__":
    main()
