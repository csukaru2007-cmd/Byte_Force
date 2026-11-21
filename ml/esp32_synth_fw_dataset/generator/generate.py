#!/usr/bin/env python3
"""Generate the synthetic ESP32 firmware-security dataset.

usage: python3 generate.py OUT_DIR [seed]
"""
import csv
import json
import math
import os
import random
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scenarios import SCENARIOS, TRUSTED  # noqa: E402

VARIANTS = 4
LABEL_ID = {"GREEN": 0, "YELLOW": 1, "RED": 2}


def lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def norm(n):
    return re.sub(r"[^a-z0-9]", "", n.lower())


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


def extract(project_dir, deps):
    text = ""
    exts = (".ino", ".cpp", ".h", ".py", ".json", ".ini")
    for root, _, fs in os.walk(project_dir):
        for f in sorted(fs):
            if f.endswith(exts) and f != "dependency_manifest.json":
                text += open(os.path.join(root, f), errors="ignore").read() + "\n"
    feats = {k: len(re.findall(p, text)) for k, p in PATTERNS.items()}
    feats = {k: (1 if v else 0) if k != "f_http_plain_url" else min(v, 3) for k, v in feats.items()}
    # auth_present must not trigger on OTA_TOKEN declared but unused: fine for synthetic data
    # dependency features
    names_ = [d["name"] for d in deps]
    feats["d_n_deps"] = len(deps)
    feats["d_any_unverified"] = int(any(not d["publisher_verified"] for d in deps))
    feats["d_min_log_downloads"] = round(min([math.log10(d["downloads"] + 1) if d["downloads"] else 0 for d in deps] or [7]), 2)
    feats["d_any_incomplete_meta"] = int(any((not d["has_repo"]) or (not d["license"]) or (not d["has_author"]) for d in deps))
    feats["d_any_vendored"] = int(any(d["vendored"] for d in deps))
    sims = []
    for n in names_:
        for t in TRUSTED:
            if norm(n) != norm(t):
                sims.append(lev(norm(n), norm(t)))
    feats["d_min_name_edit_dist"] = min(sims) if sims else 99
    feats["d_name_lookalike"] = int(feats["d_min_name_edit_dist"] <= 2 or any(norm(t) in norm(n) and norm(t) != norm(n) for n in names_ for t in TRUSTED))
    feats["loc"] = text.count("\n")
    return feats, text


def main(out, seed=1337):
    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(os.path.join(out, "projects"))
    rows, jsonl = [], []
    n = 0
    for sid, cat, label, desc, fn in SCENARIOS:
        for v in range(VARIANTS):
            n += 1
            rng = random.Random(f"{seed}-{sid}-{v}")
            r = fn(rng, v)
            pid = "P%03d_%s_v%d" % (n, sid, v)
            pdir = os.path.join(out, "projects", pid)
            for rel, content in r["files"].items():
                p = os.path.join(pdir, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f:
                    f.write(content)
            with open(os.path.join(pdir, "dependency_manifest.json"), "w") as f:
                json.dump(r["deps"], f, indent=2)
            feats, text = extract(pdir, r["deps"])
            row = dict(project_id=pid, scenario_id=sid, category=cat, scenario=desc, label=label,
                       label_id=LABEL_ID[label], variant=v, language=r["language"],
                       split="test" if v == 3 else "train", edge_case=int(r["edge"]),
                       n_files=len(r["files"]), rationale=r["rationale"])
            row.update(feats)
            rows.append(row)
            jsonl.append(dict(project_id=pid, scenario_id=sid, label=label, split=row["split"],
                              deps=r["deps"], code=text))
    with open(os.path.join(out, "labels.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(out, "dataset.jsonl"), "w") as f:
        for j in jsonl:
            f.write(json.dumps(j) + "\n")
    print("projects:", n)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 1337)
