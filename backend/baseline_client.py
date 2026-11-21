"""Client for the separate LLM-only baseline service (shipsafe_baseline, POST /api/v1/scan).

The baseline is our own LLM code-review service, not a third-party scanner. It is called only
when SHIPSAFE_BASELINE_URL is set; otherwise the comparison is reported as unavailable.
Its result is shown for comparison and never influences the upload decision.
"""

from __future__ import annotations

import os

import httpx

SEVERITY_TO_CLASS = {"Critical": "RED", "High": "RED", "Medium": "YELLOW", "Low": "GREEN", "Informational": "GREEN"}


def baseline_status() -> dict:
    url = os.environ.get("SHIPSAFE_BASELINE_URL", "").strip()
    return {"configured": bool(url)}


def run_baseline(zip_bytes: bytes, filename: str) -> dict:
    url = os.environ.get("SHIPSAFE_BASELINE_URL", "").strip().rstrip("/")
    label = "LLM-only baseline (shipsafe_baseline service) - our own comparison system, not a third-party scanner"
    if not url:
        return {"status": "unavailable", "label": label,
                "reason": "SHIPSAFE_BASELINE_URL is not configured, so the baseline was not run."}
    headers = {}
    if os.environ.get("SHIPSAFE_BASELINE_API_KEY"):
        headers["X-API-Key"] = os.environ["SHIPSAFE_BASELINE_API_KEY"]
    try:
        response = httpx.post(f"{url}/api/v1/scan", files={"files": (filename, zip_bytes, "application/zip")},
                              headers=headers, timeout=float(os.environ.get("SHIPSAFE_BASELINE_TIMEOUT", "300")))
        data = response.json()
    except Exception as error:  # noqa: BLE001
        return {"status": "unavailable", "label": label, "reason": f"Baseline request failed: {error}"}
    if response.status_code >= 400 and not isinstance(data.get("findings"), list):
        return {"status": "unavailable", "label": label,
                "reason": f"Baseline returned HTTP {response.status_code}: {data.get('detail') or data}"}
    findings = [{"rule_id": f.get("rule_id"), "title": f.get("title"), "severity": f.get("severity"),
                 "file": f.get("file"), "line": f.get("line"), "category": f.get("category")}
                for f in data.get("findings", [])]
    classes = [SEVERITY_TO_CLASS.get(f["severity"], "YELLOW") for f in findings]
    risk = "RED" if "RED" in classes else "YELLOW" if "YELLOW" in classes else "GREEN"
    if data.get("status") != "completed" and risk == "GREEN":
        risk = "YELLOW"
    return {"status": data.get("status", "unknown"), "label": label, "risk_class": risk,
            "risk_class_rule": "Critical/High -> RED, Medium -> YELLOW, otherwise GREEN (mapping applied by ShipSafe)",
            "model": (data.get("model") or {}).get("models_served") or (data.get("model") or {}).get("model_requested"),
            "findings": findings, "errors": data.get("errors", [])[:10],
            "duration_seconds": data.get("scan_duration_seconds")}
