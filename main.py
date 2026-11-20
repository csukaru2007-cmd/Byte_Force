"""ShipSafe - check an AI-generated ESP32 PlatformIO project for risky dependencies.

Usage (PowerShell; quote the path because ours contains a comma):
    uv run python main.py "path\\to\\project"
    uv run python main.py "path\\to\\project" --offline     # use cache.json only

It prints a report and saves report.json inside the project folder.
Exit code: 0 = GOOD, 2 = MEDIUM, 1 = CRITICAL (so a build script can stop on CRITICAL).

Safety: only registry metadata is read. Nothing is ever downloaded, installed or published.
"""

import argparse
import json
import sys
import time
from pathlib import Path

from checker.registry import Registry
from checker.rules import Trusted, check_project

EXIT_CODES = {"GOOD": 0, "CRITICAL": 1, "MEDIUM": 2}
ICONS = {"CRITICAL": "[CRITICAL]", "MEDIUM": "[MEDIUM]  "}


def print_report(report: dict) -> None:
    print()
    print(f"ShipSafe report for '{report['project']}'")
    print(f"Checked {len(report['dependencies'])} lib_deps entries in {report['seconds']} s")
    print("-" * 70)
    if not report["findings"]:
        print("No problems found.")
    for f in report["findings"]:
        print(f"{ICONS[f['severity']]} {f['issue']:<19} {f['library']}")
        print(f"             {f['explanation']}")
        print(f"             suggested lib_deps line: {f['suggested_fix']}")
        print()
    print("-" * 70)
    print(f"VERDICT: {report['verdict']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a PlatformIO project's dependencies.")
    parser.add_argument("folder", help="folder that contains platformio.ini")
    parser.add_argument("--offline", action="store_true", help="only use cache.json, no network")
    parser.add_argument("--quiet", action="store_true", help="only print the verdict")
    args = parser.parse_args()

    folder = Path(args.folder).resolve()
    registry = Registry(offline=args.offline)
    start = time.perf_counter()
    try:
        report = check_project(folder, registry, Trusted())
    except FileNotFoundError as error:
        print(f"Error: {error}")
        return 3
    finally:
        registry.save()          # keep whatever we learned in cache.json
    report["seconds"] = round(time.perf_counter() - start, 2)

    (folder / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.quiet:
        print(f"ShipSafe verdict: {report['verdict']} ({len(report['findings'])} findings)")
    else:
        print_report(report)
        print(f"Saved {folder / 'report.json'}")
    return EXIT_CODES[report["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
