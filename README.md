# ShipSafe

Explainable, hardware-aware security analysis for **ESP32 / Arduino PlatformIO projects**.

Upload a PlatformIO project as a ZIP. ShipSafe runs three deterministic components and
returns one report in which every finding has a rule ID, severity, file and line, evidence,
an explanation and a recommendation:

| Component | What it checks | Knowledge source |
|---|---|---|
| **PlatformIO intelligence** | dependency identity, publisher, metadata consistency, look-alike names | live PlatformIO Registry API + `databases/trusted_packages.json` |
| **Hardware intelligence** | GPIO use against the selected chip (input-only, flash, strapping, ADC/DAC/touch, ...) | `databases/esp32_wroom_32.json`, built from the Espressif datasheet |
| **Security engine** | network behaviour, credential exposure, dynamic execution, firmware operations, obfuscation | Clang AST + `databases/security_rules.json` |

ShipSafe **never builds or runs uploaded code** (no `pio run`, no `extra_scripts`), uses **no
LLM and no third-party scanner** for its verdicts, and **does not claim that a finding proves
malware**. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it works.

---

## Why ShipSafe changed direction

ShipSafe started as a different project. Earlier versions are still in the git history.

| Version | What it was | Where |
|---|---|---|
| 1. LangGraph agent | A security gate for AI-generated **Python web apps**. Bandit, Semgrep, Gitleaks, detect-secrets, pip-audit and an authz AST check ran as parallel LangGraph nodes. **Gemini** triaged the merged findings, and a policy step decided block/review/deploy. Deployed on Vercel. | PR #1, commit `53e69a8` |
| 2. Dependency checker | Deterministic `platformio.ini` checker for ESP32 projects (hallucinated, impersonating or typosquatted libraries). Tested against a Gemini-only baseline. | commit `321585d` |
| 3. **Current version** | Hardware-aware analysis of whole PlatformIO projects: dependency intelligence, a GPIO check against the ESP32 datasheet, and a Clang-AST security engine. No LLM. | this tree |

### Why we removed the LLM and LangGraph

* **We measured it.** We ran the same 25 labelled ESP32 projects through version 2 and through a Gemini-only reviewer (`gemini-3.5-flash-lite`):

  | | Deterministic rules | Gemini only |
  |---|---|---|
  | Correct verdicts | **25 / 25** | 14 / 25 |
  | Clean projects wrongly flagged | 0 | 2 |
  | Vulnerable projects wrongly passed | 0 | 6 |
  | Bad libraries found / missed / false alarms | 22 / 0 / 0 | 13 / 9 / 5 |
  | Total time, tokens | 0.03 s, 0 | ~24 s, 5,912 |

  Gemini said that real, published versions "do not exist" (Adafruit GFX 1.13.0,
  ESPAsyncWebServer 3.12.1). It also passed forks that impersonate WiFiManager, PubSubClient
  and FastLED.
* **An LLM can't reliably check another LLM.** The main risk in AI-generated firmware is
  hallucinated or wrong facts: libraries that don't exist, wrong owners, unsafe pins. A
  second model guessing at the same facts repeats that failure. The true answers are
  available: the PlatformIO Registry API and Espressif's datasheet. ShipSafe looks them up.
* **A security verdict must be reproducible and explainable.** The same project must
  always get the same report. Every finding has a rule ID, a file and line, and evidence a
  reviewer can check. Model output changes from run to run and can't be audited the same way.
* **LangGraph added nothing we needed.** Once triage was deterministic, the pipeline was a
  straight line of steps. The graph framework, the LangChain dependencies and the API keys
  were extra cost and failure points. Now each stage is a plain Python function. A failing
  stage is reported in `errors` and the other stages still run.
* **No API key, no network required.** The analysis runs offline (cached registry answers)
  and costs nothing per scan.

### Why we moved to hardware (ESP32 / PlatformIO)

* **Python web apps already have good scanners.** Version 1 was mostly a wrapper around
  Bandit, Semgrep, Gitleaks and pip-audit. Those tools are mature, and the wrapper added
  little on top.
* **Embedded projects have almost nothing.** AI assistants write a lot of Arduino/ESP32
  code, and no tool checks a PlatformIO project's dependencies and pin usage together.
* **Hardware mistakes have physical consequences.** Driving input-only GPIO34 as an
  output, using flash pins (GPIO6–11), or pulling a strapping pin the wrong way can stop a
  board from booting or damage it. These are fixed facts in a datasheet, so they suit
  deterministic rules that cite their source.
* **Firmware is hard to update.** A malicious or impersonating library, hidden network
  calls, or a hardcoded credential in a shipped device is costly to fix in the field. So
  we review the project before it is built and flashed.

---

## Setup on Windows

Requirements: Windows 10/11, **Python 3.12** (64-bit). No separate LLVM/Clang install is
needed: the `libclang` Python wheel ships the Clang 18 front end. PlatformIO itself is optional.

```powershell
cd path\to\AI_AGENT
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
python -m pip install -r requirements.txt
```

With [uv](https://docs.astral.sh/uv/) instead: `uv sync` (uses `pyproject.toml` / `uv.lock`).

Check the installation:

```powershell
python -m pytest                      # 159 tests, no network access needed
```

## Run

```powershell
python -m uvicorn backend.main:app --port 8000
```

Open <http://127.0.0.1:8000>, choose a ZIP of a PlatformIO project (the folder that contains
`platformio.ini`), pick a chip profile or leave **Auto-detect**, and press **Scan project**.

### Demonstration

1. Start the server as above and open <http://127.0.0.1:8000>.
2. Press **Scan demo project**. This scans `samples/demo_project` live — a clearly labelled
   weather-station sample with deliberate, harmless issues (fake credentials, documentation-range
   IP addresses). Its README lists what should be found.
3. Walk through the tabs: *Unified report* (filter by severity/component), *Dependency
   intelligence* (real registry metadata: owner, latest version, repository, retrieval time),
   *Hardware* (pin usage table vs. the ESP32-WROOM-32 profile), *Security patterns*, and
   *Scan issues* (parser errors, stubbed headers, registry problems).
4. Show resilience: choose **Registry metadata → Cached answers only (offline)** with an empty
   cache, or disconnect the network. The scan still completes; dependency metadata is marked
   unavailable (PKG008) and the report says the assessment is PARTIAL.
5. Show hardware profiles: scan the demo with chip **ESP32-S3** → hardware checks are skipped
   with an explicit message instead of using the wrong pin database.

Without the browser:

```powershell
curl.exe -F "file=@C:\path\to\project.zip" -F "chip=ESP32-WROOM-32" http://127.0.0.1:8000/api/scan
curl.exe http://127.0.0.1:8000/api/scan/<scan_id>
curl.exe -X POST http://127.0.0.1:8000/api/scan/demo
```

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/scan` | multipart `file` (.zip), optional `chip` (profile id/alias, empty = auto), optional `registry` (`online`/`offline`). Returns `202 {scan_id, status}` |
| POST | `/api/scan/demo` | scan the bundled demo project (report has `"demo": true`) |
| GET | `/api/scan/{scan_id}` | status and stage; the full report once `status == "completed"` |
| GET | `/api/profiles` | chip profiles (`esp32_wroom_32` supported; S2/S3/C3/C6/H2 listed as unsupported) |
| GET | `/api/health` | backend, Clang and rule-catalog status |

The report contains `project`, `summary`, `package_results`, `hardware_results`,
`hardware_analysis`, `security_results`, `security_analysis`, `findings` (all components,
unified format), `errors`, `risk_assessment`, `analysis` and `disclaimer`.

## Tests

```powershell
python -m pytest                                  # unit + integration (mocked registry)
$env:SHIPSAFE_LIVE = "1"; python -m pytest -m live   # optional: real PlatformIO Registry
```

`tests/fixtures/` holds harmless projects: `benign/` (normal Wi-Fi, sensor, OTA code that must
not be flagged above LOW), `suspicious_indicators/` (look-alike package, fake hardcoded
credential, unexpected network call in a sensor library, encoded data written to flash,
dynamic execution, firmware operations) and `hardware/` (GPIO34 output/input, GPIO23 output,
a project exercising every hardware rule, wrong/unknown boards).

## Project layout

```
backend/
  main.py                FastAPI app (API + static frontend)
  scan_service.py        pipeline orchestration, scan store
  project_loader.py      ZIP validation and safe extraction
  models.py              unified Finding / ScanIssue format
  risk_engine.py         explainable review-priority score
  platformio/            Component A: ini_parser, registry_client, similarity, package_intel
  hardware/              Component B: profiles, checker
  ast_engine/            clang_parser, compile_context, ast_extractor, runner, stubs/
  security_engine/       Component C: rule_loader, base, *_detector.py, engine
databases/
  esp32_wroom_32.json    hardware profile (generated by scripts/build_esp32_profile.py)
  board_profiles.json    PlatformIO board -> MCU (scripts/build_board_index.py)
  trusted_packages.json  verified packages (scripts/verify_trusted_packages.py)
  framework_libraries.json, package_rules.json, hardware_rules.json, security_rules.json
  reference/             team-provided DevKit V1 pin reference (cross-checked by tests)
frontend/                index.html, styles.css, app.js
samples/demo_project/    labelled demo project
scripts/                 database builders, similarity calibration, fixture generator
tests/                   unit/, integration/, fixtures/
docs/                    ARCHITECTURE.md, similarity_calibration.json
```

Regenerate the databases (network access needed):

```powershell
python -m scripts.verify_trusted_packages   # registry + GitHub verification of the trusted list
python -m scripts.build_board_index         # board list from the registry
python -m scripts.build_esp32_profile       # profile from the transcribed datasheet tables
python -m scripts.calibrate_similarity      # re-measure look-alike false positives
python -m scripts.make_fixtures             # rewrite test fixtures
```

## Configuration

Environment variables (all optional): `SHIPSAFE_CACHE_DIR` (registry cache, default
`.shipsafe_cache`), `SHIPSAFE_CACHE_TTL` (seconds, default 86400), `SHIPSAFE_SCAN_DIR`,
`SHIPSAFE_MAX_UPLOAD_MB` (25), `SHIPSAFE_MAX_UNCOMPRESSED_MB` (200), `SHIPSAFE_MAX_ENTRIES`
(5000), `SHIPSAFE_MAX_SOURCE_FILES` (400), `SHIPSAFE_SCAN_TIME_LIMIT` (300 s).

## Known limitations and unimplemented features

* **Hardware profiles:** only the original ESP32 / ESP32-WROOM-32 is implemented. ESP32-S2/S3/C3/C6/H2
  are recognised and skipped with a message. WROVER boards (PSRAM on GPIO16/17) and ESP32-PICO
  differences are not modelled; a warning is shown for WROVER board IDs.
* **Compilation context:** the real Arduino-ESP32/ESP-IDF headers are not used unless a
  `compile_commands.json` with existing include paths is supplied. By default ShipSafe parses with
  declaration-only stub headers (`backend/ast_engine/stubs`) on a generic 32-bit Clang target
  (libclang 18 has no Xtensa target). Headers that are still missing are replaced by empty files
  and reported; code depending on them may be incompletely analysed (shown as parser issues).
* **Data flow:** only intra-procedural, through plain variable assignments. No inter-procedural or
  cross-file tracking, no pointer/alias analysis. Function pointers, callbacks and virtual dispatch
  are reported as unresolved, not followed.
* **Conditional compilation:** only the configuration from `build_flags` of the analysed environment
  is seen; code in inactive `#if` branches is not analysed. Dynamic build flags (`!command`) and
  `extra_scripts` are never executed.
* **Dependencies:** library source is analysed only if it is inside the upload (`lib/`,
  `.pio/libdeps/`). ShipSafe does not download packages. Git/URL dependencies have no registry
  metadata. PlatformIO's exact resolution order for owner-less names is not reproduced.
* **Look-alike detection** protects only the 18 packages in `trusted_packages.json`. Calibration on
  1,152 real registry names found 23 legitimate packages from non-verified publishers that match a
  non-exact relation (see docs). Purpose matching for dependencies is keyword-based.
* **Credential detection** relies on identifier names, credential API positions and listed token
  formats; secrets with neutral names passed through unknown APIs are missed.
* **Risk score** is a fixed-weight review priority, not a calibrated probability; it was not
  validated against a labelled corpus of real malicious ESP32 projects (none was used).
* **Scans** are kept in memory only (lost on restart); there is no authentication on the API, so
  run it locally or behind your own access control.
* **Dashboard:** verified through the API and a JavaScript compile check; no automated browser test.
