"""Evaluate ShipSafe against hand-labelled test projects, and compare with a Gemini-only baseline.

Usage:
    uv run python eval.py              # ShipSafe (fresh cache, honest timing) + Gemini baseline
    uv run python eval.py --no-llm     # ShipSafe only
    uv run python eval.py --warm       # reuse cache.json (shows the cached speed)

test_configs/labels.json says, for every project, the expected verdict and the expected
findings as [library, issue] pairs. Labels were written from the planted flaws, BEFORE
running either system on them.

Metrics
  finding level  (ShipSafe only)  a finding is correct when library AND issue match a label
  library level  (both systems)   was each problematic lib_deps line flagged at all? Gemini does
                                  not use our issue names, so this is the fair comparison.
                                  #include problems are left out here: Gemini only sees lib_deps.
  verdict        exact CRITICAL / MEDIUM / GOOD match, clean projects wrongly flagged,
                 vulnerable projects wrongly passed as GOOD
Results are also saved to eval_results.json.
"""

import argparse
import json
import os
import re
import tempfile
import time
from pathlib import Path

from dotenv import load_dotenv

from checker.parse_ini import parse_platformio_ini
from checker.registry import Registry
from checker.rules import Trusted, check_project

GEMINI_MODEL = "gemini-3.5-flash-lite"      # change the baseline model here
SECONDS_BETWEEN_CALLS = 5                    # free tier allows only a few requests per minute
RATE_LIMIT_WAIT_SECONDS = 30                 # wait this long after an HTTP 429, then retry
CONFIG_DIR = Path(__file__).resolve().parent / "test_configs"

BASELINE_PROMPT = """You are reviewing the PlatformIO lib_deps of an AI-generated ESP32 project.
Are these dependencies correct and trustworthy?

lib_deps:
{deps}

Answer ONLY with JSON in this exact shape:
{{"verdict": "CRITICAL" | "MEDIUM" | "GOOD",
  "problems": [{{"library": "<the lib_deps line exactly as given>", "issue": "<short reason>",
                "severity": "CRITICAL" | "MEDIUM"}}]}}
Use CRITICAL for libraries that do not exist, impersonate or typosquat a known library;
MEDIUM for weaker problems (missing owner, unpinned version, untrusted source); GOOD if all are fine."""


# --------------------------------------------------------------------------- #
# Small metric helpers
# --------------------------------------------------------------------------- #

def precision_recall(tp: int, fp: int, fn: int) -> tuple[float, float]:
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return precision, recall


def label_libraries(label: dict, deps: list[str]) -> set[str]:
    """lib_deps lines that the label says have a problem (#include findings excluded)."""
    return {lib for lib, issue in label["findings"] if lib in deps}


# --------------------------------------------------------------------------- #
# ShipSafe
# --------------------------------------------------------------------------- #

def run_shipsafe(projects: list[Path], registry: Registry) -> dict[str, dict]:
    trusted = Trusted()
    results = {}
    for folder in projects:
        start = time.perf_counter()
        report = check_project(folder, registry, trusted)
        results[folder.name] = {
            "verdict": report["verdict"],
            "findings": [[f["library"], f["issue"]] for f in report["findings"]],
            "flagged_libraries": sorted({f["library"] for f in report["findings"]}),
            "seconds": time.perf_counter() - start,
        }
    return results


# --------------------------------------------------------------------------- #
# Gemini baseline
# --------------------------------------------------------------------------- #

def text_of(content) -> str:
    """LangChain message content can be a string or a list of blocks."""
    if isinstance(content, str):
        return content
    return "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in content)


def parse_baseline_answer(text: str) -> dict:
    """Pull the JSON object out of the model's answer (it sometimes wraps it in ```json)."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    try:
        data = json.loads(match.group(0)) if match else {}
    except ValueError:
        data = {}
    verdict = str(data.get("verdict", "")).upper()
    return {
        "verdict": verdict if verdict in ("CRITICAL", "MEDIUM", "GOOD") else "UNPARSEABLE",
        "problems": data.get("problems", []) if isinstance(data.get("problems"), list) else [],
    }


def match_line(name: str, deps: list[str]) -> str | None:
    """Map the library name Gemini mentions back to one of the real lib_deps lines."""
    name = str(name).strip().strip("`'\"")
    for dep in deps:
        if name == dep:
            return dep
    for dep in deps:
        if name and (name.lower() in dep.lower() or dep.lower() in name.lower()):
            return dep
    return None


def run_baseline(projects: list[Path]) -> dict[str, dict]:
    from langchain_google_genai import ChatGoogleGenerativeAI

    load_dotenv()
    llm = ChatGoogleGenerativeAI(model=GEMINI_MODEL, google_api_key=os.environ["GOOGLE_API_KEY"],
                                 temperature=0, timeout=60, max_retries=2)
    results = {}
    for folder in projects:
        deps = [d.raw for d in parse_platformio_ini(folder / "platformio.ini")]
        prompt = BASELINE_PROMPT.format(deps="\n".join(deps))
        text, usage, seconds = "", {}, 0.0
        for attempt in range(4):
            start = time.perf_counter()
            try:
                response = llm.invoke(prompt)
                text = text_of(response.content)
                usage = response.usage_metadata or {}
                seconds = time.perf_counter() - start
                break
            except Exception as error:      # count failures, do not crash the whole evaluation
                text = f"ERROR: {error}"
                if "429" in str(error) or "RESOURCE_EXHAUSTED" in str(error):
                    print(f"  gemini  rate limited, waiting {RATE_LIMIT_WAIT_SECONDS}s and retrying...")
                    time.sleep(RATE_LIMIT_WAIT_SECONDS)
                else:
                    break
        time.sleep(SECONDS_BETWEEN_CALLS)   # stay under the free tier's requests-per-minute limit
        answer = parse_baseline_answer(text) if not text.startswith("ERROR") else {"verdict": "ERROR", "problems": []}
        flagged = {match_line(p.get("library", ""), deps) for p in answer["problems"] if isinstance(p, dict)}
        results[folder.name] = {
            "verdict": answer["verdict"],
            "flagged_libraries": sorted(f for f in flagged if f),
            "seconds": seconds,
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
            "raw_answer": text[:2000],
        }
        print(f"  gemini  {folder.name:<26} {answer['verdict']:<11} {seconds:5.2f}s")
    return results


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def score(results: dict[str, dict], labels: dict[str, dict], deps_by_project: dict[str, list[str]],
          finding_level: bool) -> dict:
    s = {"tp": 0, "fp": 0, "fn": 0, "lib_tp": 0, "lib_fp": 0, "lib_fn": 0, "verdict_ok": 0,
         "clean_wrongly_flagged": 0, "vulnerable_wrongly_passed": 0, "seconds": 0.0, "tokens": 0,
         "scored": 0, "errors": 0}
    for name, label in labels.items():
        r = results[name]
        if r["verdict"] == "ERROR":     # API failure: not a wrong answer, leave it out and report it
            s["errors"] += 1
            continue
        s["scored"] += 1
        deps = deps_by_project[name]
        if finding_level:
            expected = {tuple(f) for f in label["findings"]}
            got = {tuple(f) for f in r["findings"]}
            s["tp"] += len(expected & got)
            s["fp"] += len(got - expected)
            s["fn"] += len(expected - got)
        expected_libs = label_libraries(label, deps)
        got_libs = {lib for lib in r["flagged_libraries"] if lib in deps}
        s["lib_tp"] += len(expected_libs & got_libs)
        s["lib_fp"] += len(got_libs - expected_libs)
        s["lib_fn"] += len(expected_libs - got_libs)
        s["verdict_ok"] += r["verdict"] == label["verdict"]
        s["clean_wrongly_flagged"] += label["verdict"] == "GOOD" and r["verdict"] != "GOOD"
        s["vulnerable_wrongly_passed"] += label["verdict"] != "GOOD" and r["verdict"] == "GOOD"
        s["seconds"] += r["seconds"]
        s["tokens"] += r.get("input_tokens", 0) + r.get("output_tokens", 0)
    return s


def print_table(rows: dict[str, dict], n: int, n_clean: int, n_vuln: int) -> None:
    def pct(x: float) -> str:
        return f"{x:.0%}"

    header = ["Metric"] + list(rows)
    lines = []
    for title, fn in [
        ("Projects scored (API errors)", lambda s: f"{s['scored']}/{n} ({s['errors']})"),
        ("Verdict correct", lambda s: f"{s['verdict_ok']}/{s['scored']}"),
        ("Clean projects wrongly flagged", lambda s: f"{s['clean_wrongly_flagged']}/{n_clean}"),
        ("Vulnerable projects passed as GOOD", lambda s: f"{s['vulnerable_wrongly_passed']}/{n_vuln}"),
        ("Library-level precision", lambda s: pct(precision_recall(s["lib_tp"], s["lib_fp"], s["lib_fn"])[0])),
        ("Library-level recall", lambda s: pct(precision_recall(s["lib_tp"], s["lib_fp"], s["lib_fn"])[1])),
        ("Wrongly flagged libraries", lambda s: str(s["lib_fp"])),
        ("Finding-level precision", lambda s: pct(precision_recall(s["tp"], s["fp"], s["fn"])[0]) if s.get("finding_level") else "n/a"),
        ("Finding-level recall", lambda s: pct(precision_recall(s["tp"], s["fp"], s["fn"])[1]) if s.get("finding_level") else "n/a"),
        ("Avg time per project", lambda s: f"{s['seconds'] / max(s['scored'], 1):.2f} s"),
        ("Tokens used (total)", lambda s: f"{s['tokens']:,}" if s["tokens"] else "0"),
    ]:
        lines.append([title] + [fn(s) for s in rows.values()])
    widths = [max(len(str(row[i])) for row in [header] + lines) for i in range(len(header))]
    sep = "+".join("-" * (w + 2) for w in widths)
    print(" | ".join(h.ljust(w) for h, w in zip(header, widths)))
    print(sep)
    for row in lines:
        print(" | ".join(str(c).ljust(w) for c, w in zip(row, widths)))


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ShipSafe vs a Gemini-only baseline")
    parser.add_argument("--no-llm", action="store_true", help="skip the Gemini baseline")
    parser.add_argument("--warm", action="store_true", help="use cache.json instead of a fresh cache")
    args = parser.parse_args()

    labels = json.loads((CONFIG_DIR / "labels.json").read_text(encoding="utf-8"))
    projects = [CONFIG_DIR / name for name in labels]
    deps_by_project = {p.name: [d.raw for d in parse_platformio_ini(p / "platformio.ini")] for p in projects}
    n_clean = sum(1 for l in labels.values() if l["verdict"] == "GOOD")

    # Fresh cache by default, so the timing includes the real registry lookups.
    cache = None if args.warm else Path(tempfile.mkdtemp()) / "cache.json"
    registry = Registry(cache_file=cache) if cache else Registry()
    print(f"ShipSafe on {len(projects)} projects ({'cache.json' if args.warm else 'fresh cache'})...")
    shipsafe = run_shipsafe(projects, registry)
    if args.warm:
        registry.save()

    # Per-project disagreements: the failure analysis starts here.
    for name, label in labels.items():
        r = shipsafe[name]
        expected, got = {tuple(f) for f in label["findings"]}, {tuple(f) for f in r["findings"]}
        mark = "ok " if expected == got and r["verdict"] == label["verdict"] else "XX "
        print(f"  {mark}{name:<26} expected {label['verdict']:<9} got {r['verdict']:<9} {r['seconds']:5.2f}s")
        for f in sorted(expected - got):
            print(f"       missed:        {f}")
        for f in sorted(got - expected):
            print(f"       extra finding: {f}")

    rows = {"ShipSafe (rules)": {**score(shipsafe, labels, deps_by_project, True), "finding_level": True}}
    baseline = {}
    if not args.no_llm:
        print(f"\nGemini baseline ({GEMINI_MODEL}) on {len(projects)} projects...")
        baseline = run_baseline(projects)
        rows[f"Gemini only ({GEMINI_MODEL})"] = score(baseline, labels, deps_by_project, False)

    print()
    print_table(rows, len(projects), n_clean, len(projects) - n_clean)
    Path("eval_results.json").write_text(json.dumps({"shipsafe": shipsafe, "gemini": baseline,
                                                     "summary": rows}, indent=2), encoding="utf-8")
    print("\nSaved eval_results.json")


if __name__ == "__main__":
    main()
