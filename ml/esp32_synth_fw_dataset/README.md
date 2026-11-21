# ESP32 firmware-security synthetic dataset (100 projects)

25 scenarios x 4 variants. Scenario IDs/labels are exactly your table (O, D, E, L groups).
Categories A-D from your earlier tables are NOT included yet (not in the message I received).

- labels.csv      one row per project: label (GREEN/YELLOW/RED), label_id (0/1/2), scenario, split,
                  edge_case, rationale, plus regex features (f_*, d_*) for a small classical model
- dataset.jsonl   one line per project: concatenated code + dependency metadata (for a text model)
- projects/       real file trees (src/main.cpp, platformio.ini, main.py, lib/*, dependency_manifest.json)
- generator/      regenerate with: python3 generate.py OUT_DIR [seed]

Splits: variant 0-2 = train, variant 3 = test. Variants of one scenario are siblings, so that split is
optimistic; use GroupKFold on scenario_id for an honest estimate.

Notes
- C++ not compiled (no Arduino toolchain); Python files pass py_compile, C++ brackets balance.
- All "bad" code is inert stubs: .invalid / documentation IPs, placeholder keys, no real payloads.
- Edge cases (edge_case=1): O05 v3 (HTTP + hash from same channel -> still RED), D06 v3 (name resembles a
  trusted lib but metadata healthy -> GREEN).
- To add scenarios: write a function in scenarios.py and append to SCENARIOS.
