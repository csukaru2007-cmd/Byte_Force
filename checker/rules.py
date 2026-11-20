"""The ShipSafe rules. Fixed, deterministic, no AI involved.

CRITICAL
  HALLUCINATED        the library (or owner/library) does not exist in the PlatformIO registry
  IMPERSONATION       a trusted library name, but published by a different owner
  TYPOSQUAT           an existing library whose name looks almost like a trusted one
MEDIUM
  NO_OWNER            no owner given -> PlatformIO may pick a fork with the same name
  UNTRUSTED_URL       installed from a URL that is not a trusted owner's GitHub
  UNPINNED_VERSION    no exact version -> a future (possibly malicious) release is installed silently
  VERSION_NOT_FOUND   the pinned version was never published (typical AI mistake)
  UNDECLARED_INCLUDE  the code #includes a library header that lib_deps does not declare
  REGISTRY_UNREACHABLE  we could not check (network) - never treated as "fine"

Verdict: any CRITICAL -> CRITICAL, else any MEDIUM -> MEDIUM, else GOOD.
"""

import difflib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from checker.includes import find_external_includes
from checker.parse_ini import Dependency, parse_platformio_ini
from checker.registry import Registry, RegistryError

TRUSTED_FILE = Path(__file__).resolve().parent.parent / "trusted_libs.json"

# Two names with a similarity ratio at or above this (0..1) count as "looks almost the same".
TYPOSQUAT_SIMILARITY = 0.85
# ...and their lengths (after clean_name) may differ by at most this many characters.
MAX_LENGTH_DIFFERENCE = 1

# "7.4.3" or "=7.4.3" is pinned. "^7.0.0", "~1.2", ">=1.0", "*" or nothing is not.
EXACT_VERSION = re.compile(r"^=?\s*v?\d+(\.\d+)*([-+][0-9A-Za-z.\-]+)?$")


@dataclass
class Finding:
    library: str        # the lib_deps entry (or header) the finding is about
    issue: str          # one of the codes listed at the top of this file
    severity: str       # "CRITICAL" or "MEDIUM"
    explanation: str    # plain English
    suggested_fix: str  # a corrected lib_deps line (or what to do)


# --------------------------------------------------------------------------- #
# Trusted libraries
# --------------------------------------------------------------------------- #

class Trusted:
    """Lookup helpers around trusted_libs.json."""

    def __init__(self, path: Path = TRUSTED_FILE):
        self.libraries = json.loads(path.read_text(encoding="utf-8"))["libraries"]
        self.by_name = {lib["name"].lower(): lib for lib in self.libraries}
        self.owners = set()             # registry owners we trust
        self.github_owners = set()      # GitHub accounts we trust
        self.by_header = {}             # "PubSubClient.h" -> library
        for lib in self.libraries:
            owners = [lib["owner"], *lib["also_trusted_owners"]]
            self.owners.update(o.lower() for o in owners)
            self.github_owners.update(o.lower() for o in owners)
            if lib["github"]:
                self.github_owners.add(lib["github"].split("/")[3].lower())
            for header in lib["headers"]:
                self.by_header.setdefault(header, lib)

    def owner_ok(self, lib: dict, owner: str) -> bool:
        return owner.lower() in {o.lower() for o in [lib["owner"], *lib["also_trusted_owners"]]}

    def closest_name(self, name: str) -> tuple[dict, float] | None:
        """The trusted library whose name is most similar to `name` (but not equal).

        Only names of (almost) the same length are compared: a typosquat changes one or two
        characters ("ArduinoJsn", "PubSubCIient"), while real libraries that extend a famous
        name add whole words ("FastAccelStepper", "OneWireNg", "BH1750_WE").
        """
        best, best_score = None, 0.0
        for lib in self.libraries:
            if lib["name"].lower() == name.lower():
                continue
            if abs(len(clean_name(name)) - len(clean_name(lib["name"]))) > MAX_LENGTH_DIFFERENCE:
                continue
            score = similarity(name, lib["name"])
            if score > best_score:
                best, best_score = lib, score
        return (best, best_score) if best else None


def clean_name(name: str) -> str:
    """Lowercase and drop spaces, '-' and '_' ("Adafruit_NeoPixel" -> "adafruitneopixel")."""
    return re.sub(r"[\s_\-]+", "", name.lower())


def similarity(a: str, b: str) -> float:
    """0..1 similarity of two library names (difflib), ignoring case, spaces, '-' and '_'."""
    return difflib.SequenceMatcher(None, clean_name(a), clean_name(b)).ratio()


def line_for(lib: dict, version: str | None = None) -> str:
    """A correct lib_deps line for a trusted library, pinned to an exact version."""
    return f"{lib['owner']}/{lib['name']}@{version or lib['latest_version']}"


# --------------------------------------------------------------------------- #
# Rules for one dependency
# --------------------------------------------------------------------------- #

def check_registry_dependency(dep: Dependency, registry: Registry, trusted: Trusted) -> tuple[list[Finding], dict | None]:
    """Rules for an owner/name@version entry. Returns (findings, registry package or None)."""
    findings: list[Finding] = []
    lib = trusted.by_name.get(dep.name.lower())          # is this a trusted library name?
    close = trusted.closest_name(dep.name)
    lookalike = close[0] if close and close[1] >= TYPOSQUAT_SIMILARITY else None

    # Rule: IMPERSONATION - trusted name, wrong owner
    if lib and dep.owner and not trusted.owner_ok(lib, dep.owner):
        findings.append(Finding(dep.raw, "IMPERSONATION", "CRITICAL",
            f"'{dep.name}' is a well-known library published by '{lib['owner']}', but this line installs "
            f"it from '{dep.owner}'. Anyone can publish a library under a famous name; this copy may contain "
            f"different (malicious) code.",
            line_for(lib)))
        return findings, None

    # Look the library up. With an owner we ask for exactly owner/name; without, we search by name.
    if dep.owner:
        package = registry.get_package(dep.owner, dep.name)
        exists = package is not None
        other_owners = [] if exists else registry.find_by_name(dep.name)
    else:
        matches = registry.find_by_name(dep.name)
        exists = bool(matches)
        other_owners = matches
        # The owner PlatformIO will most likely pick: the trusted one if it exists, else the most popular.
        chosen = next((m for m in matches if lib and trusted.owner_ok(lib, m["owner"])), matches[0] if matches else None)
        package = registry.get_package(chosen["owner"], chosen["name"]) if chosen else None

    # Rule: HALLUCINATED - not in the registry at all
    if not exists:
        if lib:
            fix = line_for(lib)
        elif other_owners:
            fix = f"{other_owners[0]['owner']}/{other_owners[0]['name']}@{other_owners[0]['latest_version']}"
        elif lookalike:
            fix = line_for(lookalike)
        else:
            fix = "(remove this line - no such library exists)"
        where = f"'{dep.owner}/{dep.name}'" if dep.owner else f"'{dep.name}'"
        hint = f" Did you mean '{fix}'?" if not fix.startswith("(") else ""
        findings.append(Finding(dep.raw, "HALLUCINATED", "CRITICAL",
            f"{where} does not exist in the PlatformIO registry. AI assistants often invent library names; "
            f"an attacker can register the invented name later and it would be installed automatically.{hint}",
            fix))
        return findings, None

    owner = package["owner"] if package else (dep.owner or "")

    # Rule: TYPOSQUAT - an existing library that looks almost like a trusted one.
    # Skipped when the publisher is an owner we already trust (e.g. adafruit/Adafruit BME680 Library).
    if not lib and lookalike and owner.lower() not in trusted.owners:
        findings.append(Finding(dep.raw, "TYPOSQUAT", "CRITICAL",
            f"'{dep.name}' (by '{owner}') looks almost identical to the trusted library '{lookalike['name']}' "
            f"(by '{lookalike['owner']}'), similarity {close[1]:.0%}. Look-alike names are a common way to "
            f"trick people (and AI) into installing the wrong package.",
            line_for(lookalike)))
        return findings, package

    best_line = line_for(lib) if lib else f"{owner}/{dep.name}@{package['latest_version'] if package else 'x.y.z'}"

    # Rule: NO_OWNER
    if not dep.owner:
        owners = ", ".join(sorted({m["owner"] for m in other_owners}))
        findings.append(Finding(dep.raw, "NO_OWNER", "MEDIUM",
            f"No owner is given, so PlatformIO picks a library called '{dep.name}' by itself. "
            f"The registry has {len(other_owners)} with that exact name (owners: {owners}). "
            f"Always write owner/name so a fork or fake cannot be chosen.",
            best_line if not dep.version or not EXACT_VERSION.match(dep.version)
            else f"{(lib or {}).get('owner', owner)}/{dep.name}@{dep.version}"))

    # Rule: UNPINNED_VERSION / VERSION_NOT_FOUND
    if not dep.version or not EXACT_VERSION.match(dep.version):
        what = f"the range '{dep.version}'" if dep.version else "no version"
        findings.append(Finding(dep.raw, "UNPINNED_VERSION", "MEDIUM",
            f"This line uses {what}, so every build may download a different release - including a "
            f"compromised future one. Pin an exact version you have tested.",
            best_line))
    elif package and package["versions"] and dep.version.lstrip("=v ") not in package["versions"]:
        findings.append(Finding(dep.raw, "VERSION_NOT_FOUND", "MEDIUM",
            f"Version {dep.version} of '{dep.name}' was never published (latest is {package['latest_version']}). "
            f"The build will fail or resolve to something unexpected.",
            best_line))
    return findings, package


def check_url_dependency(dep: Dependency, trusted: Trusted) -> tuple[list[Finding], dict | None]:
    """Rules for GitHub (and other) URLs. Returns (findings, trusted library it corresponds to)."""
    findings: list[Finding] = []
    lib = trusted.by_name.get(dep.name.lower().removesuffix(".git")) if dep.kind == "github" else None
    if not lib and dep.kind == "github":   # repo name may differ from the library name (e.g. pubsubclient)
        lib = next((t for t in trusted.libraries if t["github"].lower().endswith("/" + dep.name.lower())), None)
    fix = line_for(lib) if lib else "(use the PlatformIO registry form owner/name@x.y.z, or pin a reviewed commit)"

    # Rule: UNTRUSTED_URL
    if dep.kind != "github" or (dep.owner or "").lower() not in trusted.github_owners:
        source = f"the GitHub account '{dep.owner}'" if dep.kind == "github" else "a URL outside GitHub"
        extra = (f" The real '{lib['name']}' is maintained at {lib['github']}." if lib else "")
        findings.append(Finding(dep.raw, "UNTRUSTED_URL", "MEDIUM",
            f"This library is downloaded directly from {source}, which is not a trusted publisher. "
            f"URL installs skip the registry, so nobody vouches for the code.{extra}",
            fix))
    # Rule: UNPINNED_VERSION for URLs (no #tag or #commit)
    if not dep.version:
        findings.append(Finding(dep.raw, "UNPINNED_VERSION", "MEDIUM",
            "The URL has no #tag or #commit, so the build always takes whatever is newest on the default branch.",
            fix if lib else f"{dep.url.split('#')[0]}#<tag-or-commit>"))
    return findings, lib


# --------------------------------------------------------------------------- #
# Whole project
# --------------------------------------------------------------------------- #

def verdict_for(findings: list[Finding]) -> str:
    severities = {f.severity for f in findings}
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "MEDIUM" in severities:
        return "MEDIUM"
    return "GOOD"


def check_project(folder: Path, registry: Registry, trusted: Trusted) -> dict:
    """Run every rule on one PlatformIO project folder and return the report as a dict."""
    ini = folder / "platformio.ini"
    if not ini.is_file():
        raise FileNotFoundError(f"no platformio.ini in {folder}")

    deps = parse_platformio_ini(ini)
    findings: list[Finding] = []
    declared_headers: set[str] = set()      # headers provided by the libraries in lib_deps
    declared_names: list[str] = []          # names, for libraries whose headers we do not know

    for dep in deps:
        declared_names.append(dep.name)
        try:
            if dep.kind == "registry":
                new, package = check_registry_dependency(dep, registry, trusted)
                if package:
                    declared_headers.update(package["headers"])
                lib = trusted.by_name.get(dep.name.lower())
                if lib:
                    declared_headers.update(lib["headers"])
            elif dep.kind in ("github", "other") and "://" in (dep.url or ""):
                new, lib = check_url_dependency(dep, trusted)
                if lib:
                    declared_headers.update(lib["headers"])
            else:
                new = []      # local folder: nothing to look up
        except RegistryError as error:
            new = [Finding(dep.raw, "REGISTRY_UNREACHABLE", "MEDIUM",
                           f"Could not check this library ({error}). Unknown is not the same as safe - re-run.",
                           dep.raw)]
        findings += new

    # Rule: UNDECLARED_INCLUDE
    for inc in find_external_includes(folder):
        name = Path(inc.header).name
        if name in declared_headers:
            continue
        stem = Path(name).stem
        if any(similarity(stem, n.split("/")[-1]) >= 0.8 for n in declared_names):
            continue    # e.g. MyLib.h from a URL dependency called MyLib
        lib = trusted.by_header.get(name)
        findings.append(Finding(inc.header, "UNDECLARED_INCLUDE", "MEDIUM",
            f"{inc.file}:{inc.line} includes <{inc.header}>, but no library in lib_deps provides it. "
            f"PlatformIO will then search for any library with that header (or the build breaks)"
            + (f"; it belongs to '{lib['owner']}/{lib['name']}'." if lib else "."),
            line_for(lib) if lib else f"(add the library that provides {inc.header} as owner/name@x.y.z)"))

    return {
        "project": folder.name,
        "verdict": verdict_for(findings),
        "dependencies": [dep.raw for dep in deps],
        "findings": [asdict(f) for f in findings],
    }
