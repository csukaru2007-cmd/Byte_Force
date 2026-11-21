"""ShipSafe's own extraction of the ML feature vector (f_* source features, d_* dependency features).

The f_* patterns are the same regular expressions the training dataset was labelled with
(ml/esp32_synth_fw_dataset/generator/generate.py), applied to the uploaded project's files.
The d_* features are computed from ShipSafe's PlatformIO-intelligence results (registry
metadata), not from any manifest shipped with the upload.
"""

from __future__ import annotations

import math
import os
import re
from pathlib import Path

PATTERNS = {
    "f_ota_present":        r"Update\.begin|httpUpdate|ArduinoOTA|esp_ota_begin",
    "f_auth_present":       r"Authorization|Bearer|setAuthorization|requestAuthentication|setPassword|OTA_TOKEN",
    "f_hash_check":         r"mbedtls_sha256|hashMatches|sha256",
    "f_signature_check":    r"mbedtls_pk_verify|verifySignature",
    "f_https_used":         r"https://|WiFiClientSecure|setCACert",
    "f_http_plain_url":     r"http://(?!localhost|127\.0\.0\.1)",
    "f_version_check":      r"newVer\s*<=|CURRENT_VERSION",
    "f_exec_call":          r"os\.system|subprocess\.|popen\(|\bsystem\(",
    "f_shell_true":         r"shell\s*=\s*True|os\.system",
    "f_eval_exec":          r"\beval\(|\bexec\(",
    "f_decode_obfuscation": r"b64decode|a2b_base64|unhexlify|zlib\.decompress|char host\[",
    "f_external_input":     r"on_message|msg\.decode|request\.(args|json|form)|conn\.recv|wait_msg|server\.arg|msg\.payload|Serial\.readBytesUntil|server\.upload",
    "f_input_validation":   r"re\.compile|fullmatch|in ALLOWED|not in ALLOWED|ALLOWED_CMDS|strncmp|len\(cmd\)|constrain\(",
    "f_wifi_cred_read":     r"WiFi\.psk\(|WiFi\.SSID\(|getString\(\"pass",
    "f_outbound_post":      r"\.POST\(|c\.connect\(\"|\.connect\(host|beginPacket\(",
    "f_build_hook_exec":    r"extraScript|AddPreAction|urlopen|urlretrieve",
    "f_mqtt_auth":          r"MQTT_USER",
    "f_open_ota_port":      r"WiFiServer otaServer|ArduinoOTA\.begin|server\.on\(\"/(update|ota)\"",
    "f_sensor_code":        r"analogRead|pulseIn|DHT|readTemperature|ADC\(|adc\.read",
    "f_motor_camera_oled":  r"ledcWrite|esp_camera|SSD1306",
}
D_FEATURES = ["d_n_deps", "d_any_unverified", "d_min_log_downloads", "d_any_incomplete_meta",
              "d_any_vendored", "d_min_name_edit_dist", "d_name_lookalike"]
FEATURE_NAMES = list(PATTERNS) + D_FEATURES

# Trusted library names used by the dataset's d_min_name_edit_dist / d_name_lookalike features.
TRUSTED_NAMES = ["DHT sensor library", "PubSubClient", "ArduinoJson", "Adafruit SSD1306", "Adafruit GFX Library",
                 "NewPing", "ESP Async WebServer", "WiFiManager"]

SOURCE_EXTS = (".ino", ".cpp", ".c", ".h", ".hpp", ".py", ".json", ".ini")
SKIP_DIRS = {".pio", ".git", ".vscode", "node_modules"}
VERIFIED = {"verified_trusted", "verified_upstream_repository"}
NOT_A_DEPENDENCY = {"framework_component"}


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def project_text(root: Path) -> str:
    text = ""
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name.endswith(SOURCE_EXTS) and name != "dependency_manifest.json":
                text += Path(current, name).read_text(encoding="utf-8", errors="ignore") + "\n"
    return text


def source_features(text: str) -> dict[str, float]:
    counts = {k: len(re.findall(p, text)) for k, p in PATTERNS.items()}
    return {k: (min(v, 3) if k == "f_http_plain_url" else int(bool(v))) for k, v in counts.items()}


def dependency_features(deps: list[dict]) -> dict[str, float]:
    """deps: [{name, publisher_verified, downloads, has_repo, license, has_author, vendored}]"""
    feats: dict[str, float] = {"d_n_deps": len(deps),
                               "d_any_unverified": int(any(not d["publisher_verified"] for d in deps))}
    feats["d_min_log_downloads"] = round(min(
        [math.log10(d["downloads"] + 1) if d["downloads"] else 0 for d in deps] or [7]), 2)
    feats["d_any_incomplete_meta"] = int(any((not d["has_repo"]) or (not d["license"]) or (not d["has_author"])
                                             for d in deps))
    feats["d_any_vendored"] = int(any(d["vendored"] for d in deps))
    names = [d["name"] for d in deps]
    sims = [_lev(_norm(n), _norm(t)) for n in names for t in TRUSTED_NAMES if _norm(n) != _norm(t)]
    feats["d_min_name_edit_dist"] = min(sims) if sims else 99
    feats["d_name_lookalike"] = int(feats["d_min_name_edit_dist"] <= 2 or any(
        _norm(t) in _norm(n) and _norm(t) != _norm(n) for n in names for t in TRUSTED_NAMES))
    return feats


def deps_from_package_results(package_results: list[dict]) -> tuple[list[dict], list[str]]:
    """Map ShipSafe's PlatformIO-intelligence results to the dataset's dependency fields."""
    deps, notes = [], []
    for result in package_results:
        if result.get("trust_status") in NOT_A_DEPENDENCY:
            continue
        meta = result.get("metadata") or {}
        dependency = result.get("dependency") or {}
        downloads = meta.get("downloads")
        if isinstance(downloads, dict):
            downloads = downloads.get("total_in_window")
        if result.get("metadata_status") == "unavailable":
            notes.append(f"No registry metadata for {result.get('package')}; treated as missing.")
        deps.append({
            "name": dependency.get("name") or result.get("package") or "",
            "publisher_verified": result.get("trust_status") in VERIFIED,
            "downloads": downloads or 0,
            "has_repo": bool(meta.get("repository_url")),
            "license": meta.get("license"),
            "has_author": bool(meta.get("owner")),
            "vendored": result.get("trust_status") == "local_source",
        })
    return deps, notes


def extract_features(root: Path, package_results: list[dict]) -> tuple[dict[str, float], list[str]]:
    deps, notes = deps_from_package_results(package_results)
    feats = {**source_features(project_text(root)), **dependency_features(deps)}
    return {name: feats[name] for name in FEATURE_NAMES}, notes
