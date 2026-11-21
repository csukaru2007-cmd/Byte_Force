"""Build databases/trusted_packages.json from scripts/trusted_seed.json, verifying each entry.

    python -m scripts.verify_trusted_packages

For every seed entry:
  1. PlatformIO Registry: GET /v3/packages/<owner>/library/<name> must exist and be owned by <owner>
  2. The registry's repository_url must point at the stated upstream repository
  3. GitHub API: the upstream repository must exist (fork status is recorded, not assumed)
Entries that fail any check are left out and listed on the console.
No value in the output is typed by hand except the seed (name, owner, repo, aliases).
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.platformio.registry_client import RegistryClient  # noqa: E402

SEED = ROOT / "scripts" / "trusted_seed.json"
OUTPUT = ROOT / "databases" / "trusted_packages.json"


def normalise_repo(url: str | None) -> str | None:
    if not url:
        return None
    url = url.strip().lower().removeprefix("git+")
    url = re.sub(r"^(https?://|git@)", "", url).replace("github.com:", "github.com/")
    return url.removesuffix("/").removesuffix(".git")


def github_repo(full: str) -> dict | None:
    match = re.search(r"github\.com/([^/]+)/([^/]+)", full)
    if not match:
        return None
    response = requests.get(f"https://api.github.com/repos/{match.group(1)}/{match.group(2)}",
                            timeout=20, headers={"Accept": "application/vnd.github+json"})
    if response.status_code != 200:
        return None
    data = response.json()
    return {"full_name": data["full_name"], "fork": data["fork"], "archived": data["archived"],
            "parent": (data.get("parent") or {}).get("full_name")}


def verify_publisher(client: RegistryClient, owner: str, name: str, repository: str) -> tuple[dict | None, list[str]]:
    problems = []
    result = client.get_package(owner, "library", name)
    if not result.found:
        return None, [f"registry has no {owner}/{name}"]
    data = result.data
    if data["owner"]["username"].lower() != owner.lower():
        problems.append(f"registry owner is {data['owner']['username']}")
    if normalise_repo(data.get("repository_url")) != normalise_repo(repository):
        problems.append(f"registry repository_url {data.get('repository_url')!r} != {repository!r}")
    gh = github_repo(repository)
    if gh is None:
        problems.append(f"GitHub repository {repository} not found")
    return {
        "registry_owner": data["owner"]["username"],
        "registry_id": data.get("id"),
        "registry_repository_url": data.get("repository_url"),
        "github": gh,
        "retrieved_at": result.retrieved_at,
    }, problems


def main() -> int:
    seed = json.loads(SEED.read_text(encoding="utf-8"))
    client = RegistryClient(ttl_seconds=0)          # always ask the live registry
    verified, rejected = [], []
    for entry in seed["packages"]:
        info, problems = verify_publisher(client, entry["registry_owner"], entry["canonical_name"],
                                          entry["repository"])
        if problems:
            rejected.append((entry["canonical_name"], problems))
            continue
        additional = []
        for extra in entry.get("additional_publishers", []):
            extra_info, extra_problems = verify_publisher(client, extra["registry_owner"],
                                                          entry["canonical_name"], extra["repository"])
            if extra_problems:
                rejected.append((f"{entry['canonical_name']} (publisher {extra['registry_owner']})", extra_problems))
                continue
            additional.append({"registry_owner": extra_info["registry_owner"],
                               "registry_id": extra_info["registry_id"],
                               "repository": extra["repository"], "reason": extra["reason"],
                               "github": extra_info["github"]})
        verified.append({
            "canonical_name": entry["canonical_name"],
            "registry_owner": info["registry_owner"],
            "registry_id": info["registry_id"],
            "repository": entry["repository"],
            "registry_repository_url": info["registry_repository_url"],
            "aliases": entry.get("aliases", []),
            "additional_verified_publishers": additional,
            "github": info["github"],
            "trusted_reason": "Registry owner and repository_url match the upstream project repository",
            "verification_source": "PlatformIO Registry API package endpoint + GitHub repository API",
            "verified_at": info["retrieved_at"],
        })
        print(f"  verified  {info['registry_owner']}/{entry['canonical_name']} (id {info['registry_id']})")
    for name, problems in rejected:
        print(f"  REJECTED  {name}: {'; '.join(problems)}")
    OUTPUT.write_text(json.dumps({
        "_comment": "Generated by scripts/verify_trusted_packages.py. Do not edit by hand; edit scripts/trusted_seed.json and re-run.",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "packages": verified,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(verified)} verified packages to {OUTPUT.relative_to(ROOT)}")
    return 0 if not rejected else 1


if __name__ == "__main__":
    raise SystemExit(main())
