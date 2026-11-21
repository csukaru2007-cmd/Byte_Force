"""Measure how the similarity rules behave on real registry package names.

    python -m scripts.calibrate_similarity

For every trusted package, the registry is searched with its distinctive words and every
returned library name is compared with the trusted database. The output shows how many
real, existing packages fall into each relation type, split by whether the publisher is
a verified publisher of the matched trusted package. Results are written to
docs/similarity_calibration.json and summarised in docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.platformio.package_intel import load_trusted_packages, verified_owners  # noqa: E402
from backend.platformio.registry_client import RegistryClient  # noqa: E402
from backend.platformio.similarity import best_match, tokens  # noqa: E402


def main() -> None:
    trusted = load_trusted_packages()
    client = RegistryClient()
    seen: dict[tuple[str, str], None] = {}
    for entry in trusted:
        words = [w for w in tokens(entry["canonical_name"]) if w not in ("adafruit", "sensor")] or tokens(entry["canonical_name"])
        for query in {" ".join(words), entry["canonical_name"]}:
            result = client.search(f"type:library {query}", limit=50)
            for item in result.data["items"]:
                seen[(item["owner"]["username"], item["name"])] = None

    counts = collections.Counter()
    examples = collections.defaultdict(list)
    for owner, name in seen:
        match = best_match(name, trusted)
        if match is None:
            counts["no_relation"] += 1
            continue
        same_publisher = owner.lower() in verified_owners(match.trusted_entry)
        key = f"{match.relation}:{'verified_publisher' if same_publisher else 'other_publisher'}"
        counts[key] += 1
        if len(examples[key]) < 8:
            examples[key].append(f"{owner}/{name} ~ {match.trusted_name} ({match.difference}, score {match.similarity_score})")

    report = {"registry_names_compared": len(seen), "counts": dict(sorted(counts.items())),
              "examples": dict(sorted(examples.items()))}
    out = ROOT / "docs" / "similarity_calibration.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
