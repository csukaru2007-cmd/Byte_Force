# ShipSafe

Checks AI-generated **ESP32 PlatformIO** projects for vulnerable or impersonating dependencies.
It reads only registry metadata. It never downloads, installs or publishes a library.

```powershell
uv sync
uv run python main.py "test_configs\mixed_smart_plant"     # prints a report, saves report.json
uv run python eval.py                                      # 25 labelled projects + Gemini baseline
uv run python eval.py --no-llm                             # ShipSafe only
```

Exit codes from `main.py`: `0` GOOD · `2` MEDIUM · `1` CRITICAL.

## What it checks

| Severity | Issue | Meaning |
|---|---|---|
| CRITICAL | `HALLUCINATED` | library (or owner/library) does not exist in the PlatformIO registry |
| CRITICAL | `IMPERSONATION` | trusted library name, different owner (forks, owner typos) |
| CRITICAL | `TYPOSQUAT` | existing library whose name is ≥ 85 % similar to a trusted one (difflib), same length ±1 |
| MEDIUM | `NO_OWNER` | `ArduinoJson` instead of `bblanchon/ArduinoJson` |
| MEDIUM | `UNTRUSTED_URL` | installed from a URL that is not a trusted owner's GitHub |
| MEDIUM | `UNPINNED_VERSION` | no exact version (`^7.0.0`, none, or a URL without `#tag`) |
| MEDIUM | `VERSION_NOT_FOUND` | pinned version was never published |
| MEDIUM | `UNDECLARED_INCLUDE` | `#include` of a library header that lib_deps does not declare |
| MEDIUM | `REGISTRY_UNREACHABLE` | could not check. Unknown is never treated as safe |

Verdict: any CRITICAL → CRITICAL, else any MEDIUM → MEDIUM, else GOOD. No LLM is involved.

## Files

- `main.py`: command line entry point
- `checker/parse_ini.py`: reads `lib_deps` (owner/name@version, bare names, GitHub URLs, `${common.lib_deps}`)
- `checker/registry.py`: PlatformIO registry API, with answers cached in `cache.json`
- `checker/rules.py`: the rules above
- `checker/includes.py`: finds `#include`s that need an external library
- `trusted_libs.json`: 36 popular libraries. Owners, repos, versions and headers come from the registry API.
- `eval.py`, `test_configs/`, `labels.json`: evaluation against a Gemini-only baseline
- `shipsafe_hook.py`: optional PlatformIO `extra_scripts = pre:` hook that stops the build on CRITICAL
