"""Shared helpers for the security detectors.

* API matching against the declaration Clang resolved (class, object type, base classes)
* dependency purpose context (registry metadata / library manifests)
* secret redaction
* a small intra-procedural data-flow tracker
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from backend.ast_engine.ast_extractor import FileFeatures, ProjectFeatures
from backend.models import Finding, raise_severity
from backend.platformio.ini_parser import read_installed_package
from backend.security_engine.rule_loader import RuleCatalog, security_rules

COMPONENT = "security_engine"

PURPOSE_KEYWORDS = {
    "network": ["wifi", "wi-fi", "network", "http", "https", "mqtt", "web", "server", "client", "iot", "cloud",
                "socket", "tcp", "udp", "internet", "ethernet", "websocket", "api", "ntp", "telegram", "blynk",
                "firebase", "aws", "azure", "email", "smtp", "dns", "mdns", "ota", "rest", "online", "remote"],
    "firmware": ["ota", "update", "firmware", "bootloader", "partition", "flash", "upgrade"],
    "storage": ["flash", "eeprom", "storage", "filesystem", "spiffs", "littlefs", "nvs", "preferences", "partition",
                "fat", "sd card", "logger", "logging"],
    "execution": ["interpreter", "script", "scripting", "lua", "javascript", "python", "basic", "virtual machine",
                  "plugin", "loader", "elf", "dynamic"],
}


# ------------------------------------------------------------------ API matching

def call_types(call: dict) -> set[str]:
    return {call.get("class_name"), call.get("object_type"), *call.get("object_bases", [])} - {None}


def matches_api(call: dict, api: str) -> bool:
    """'Class::method' or 'function' (free function, or unresolved call with that name)."""
    if "::" in api:
        cls, _, method = api.rpartition("::")
        if call["name"] != method:
            return False
        if cls in call_types(call):
            return True
        qualified = call.get("qualified_name") or ""
        return qualified == api or qualified.endswith("::" + api)
    if call["name"] != api:
        return False
    return call.get("class_name") is None


def first_match(call: dict, apis) -> str | None:
    for api in apis:
        if matches_api(call, api):
            return api
    return None


def call_label(call: dict, max_args: int = 3) -> str:
    args = [redact_url(a["text"]) for a in call["arguments"] if a["text"]][:max_args]
    return f"{call['display']}({', '.join(args)}{', ...' if len(call['arguments']) > max_args and args else ''})"


# ------------------------------------------------------------------ redaction

def redact(value: str) -> str:
    """Never reveal a secret: first two characters, a mask, and the length."""
    if value is None:
        return "<none>"
    if len(value) <= 4:
        return "*" * len(value) + f" ({len(value)} chars)"
    return value[:2] + "*" * min(len(value) - 2, 8) + f" ({len(value)} chars)"


_QUERY_SECRET = re.compile(r"(?i)([?&](?:[a-z_]*?(?:token|key|apikey|api_key|password|pass|secret|auth|sig)[a-z_]*)=)([^&#\s]+)")


def redact_url(url: str) -> str:
    return _QUERY_SECRET.sub(lambda m: m.group(1) + redact(m.group(2)).split(" ")[0], url)


# ------------------------------------------------------------------ dependency purpose

@dataclass
class Purpose:
    text: str
    source: str

    def mentions(self, category: str) -> bool:
        lowered = self.text.lower()
        return any(re.search(r"\b" + re.escape(word) + r"\b", lowered) for word in PURPOSE_KEYWORDS[category])

    def summary(self) -> str:
        return self.text if len(self.text) <= 120 else self.text[:117] + "..."


def _manifest_purpose(folder: Path) -> Purpose | None:
    parts = []
    try:
        manifest = json.loads((folder / "library.json").read_text(encoding="utf-8", errors="replace"))
        if isinstance(manifest, dict):
            parts.append(str(manifest.get("description") or ""))
            keywords = manifest.get("keywords")
            parts.append(" ".join(keywords) if isinstance(keywords, list) else str(keywords or ""))
    except (OSError, ValueError):
        pass
    properties = folder / "library.properties"
    if properties.is_file():
        for line in properties.read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, value = line.partition("=")
            if key.strip() in ("sentence", "paragraph", "category"):
                parts.append(value.strip())
    text = " ".join(p for p in parts if p).strip()
    return Purpose(text, f"{folder.name} library manifest") if text else None


def build_purposes(root: Path, package_results: list[dict] | None) -> dict[str, Purpose]:
    """Map lower-cased dependency folder/package names to their stated purpose."""
    purposes: dict[str, Purpose] = {}
    for result in package_results or []:
        meta = result.get("metadata") or {}
        text = " ".join(filter(None, [meta.get("description") or "", " ".join(meta.get("keywords") or [])])).strip()
        if text:
            purpose = Purpose(text, f"PlatformIO Registry metadata of {result['package']}")
            purposes[result["dependency"]["name"].lower()] = purpose
            installed = result["dependency"].get("installed") or {}
            if installed.get("folder"):
                purposes.setdefault(installed["folder"].lower(), purpose)
    folders = []
    if (root / "lib").is_dir():
        folders += [p for p in (root / "lib").iterdir() if p.is_dir()]
    libdeps = root / ".pio" / "libdeps"
    if libdeps.is_dir():
        for env_dir in libdeps.iterdir():
            if env_dir.is_dir():
                folders += [p for p in env_dir.iterdir() if p.is_dir()]
    for folder in folders:
        key = folder.name.lower()
        if key in purposes:
            continue
        purpose = _manifest_purpose(folder)
        if purpose is None:
            name = (read_installed_package(folder).get("name") or "").lower()
            purpose = purposes.get(name)
        if purpose:
            purposes[key] = purpose
    return purposes


# ------------------------------------------------------------------ detection context

@dataclass
class DetectionContext:
    features: ProjectFeatures
    purposes: dict[str, Purpose] = field(default_factory=dict)
    rules: RuleCatalog = field(default_factory=security_rules)

    def purpose_for(self, origin: str) -> Purpose | None:
        if not origin.startswith("dependency:"):
            return None
        return self.purposes.get(origin.split(":", 1)[1].lower())

    def contextual(self, base: str, origin: str, category: str) -> tuple[str, str, bool | None]:
        """(severity, explanation of context, purpose_mismatch). Raises severity one level when the
        dependency's stated purpose does not explain the behaviour."""
        if origin == "project":
            return base, "Found in the project's own source code.", False
        purpose = self.purpose_for(origin)
        name = origin.split(":", 1)[1]
        if purpose is None:
            return base, f"Found in dependency '{name}'; its purpose is unknown (no registry metadata or manifest).", None
        if purpose.mentions(category):
            return base, f"Found in dependency '{name}'; consistent with its stated purpose ({purpose.source}: '{purpose.summary()}').", False
        return (raise_severity(base),
                f"Found in dependency '{name}', whose stated purpose does not mention this behaviour "
                f"({purpose.source}: '{purpose.summary()}').", True)

    def finding(self, rule_id: str, features: FileFeatures, line: int | None, evidence: str, **kwargs) -> Finding:
        details = kwargs.pop("details", {})
        details.setdefault("enclosing_function", kwargs.pop("function", None))
        return self.rules.finding(rule_id, file=features.file, line=line, evidence=evidence,
                                  origin=features.origin, details=details, **kwargs)


# ------------------------------------------------------------------ data flow

def functions(features: FileFeatures) -> dict[str, dict]:
    """Group a file's calls, declarations and assignments by enclosing function."""
    grouped: dict[str, dict] = {}

    def bucket(name: str) -> dict:
        return grouped.setdefault(name, {"calls": [], "vars": [], "assignments": [], "casts": []})

    for call in features.function_calls:
        bucket(call["enclosing_function"])["calls"].append(call)
    for var in features.variable_declarations:
        bucket(var["enclosing_function"])["vars"].append(var)
    for assignment in features.assignments:
        bucket(assignment["enclosing_function"])["assignments"].append(assignment)
    for cast in features.function_pointer_casts:
        bucket(cast["enclosing_function"])["casts"].append(cast)
    return grouped


def _key(ref: dict) -> str:
    return ref.get("usr") or ref["name"]


@dataclass
class Taint:
    """Tracks which variables of one function carry data from a set of sources."""
    tainted: dict[str, str] = field(default_factory=dict)      # variable key -> description of source

    def add(self, key: str, reason: str) -> None:
        self.tainted.setdefault(key, reason)

    def reason_for_arg(self, arg: dict, source_calls: dict[str, str]) -> str | None:
        for ref in arg["references"]:
            if _key(ref) in self.tainted:
                return f"{ref['name']} <- {self.tainted[_key(ref)]}"
        for callee in arg["calls"]:
            if callee in source_calls:
                return source_calls[callee]
        return None


def track(function: dict, source_specs: dict[str, str], seeds: dict[str, str] | None = None) -> tuple[Taint, dict[str, str]]:
    """Propagate taint inside one function.

    source_specs: {api: "return" | "arg:N"}. Returns the taint state and a map of
    source-call qualified names -> description (for direct use as an argument).
    """
    taint = Taint()
    for key, reason in (seeds or {}).items():
        taint.add(key, reason)
    direct_sources: dict[str, str] = {}
    for call in function["calls"]:
        api = first_match(call, source_specs)
        if api is None:
            continue
        description = f"{call['display']}() at line {call['line']}"
        spec = source_specs[api]
        if spec == "return":
            direct_sources[call.get("qualified_name") or call["name"]] = description
        elif spec.startswith("arg:"):
            index = int(spec.split(":")[1])
            if index < len(call["arguments"]):
                for ref in call["arguments"][index]["references"]:
                    taint.add(_key(ref), description)
    # variables initialised or assigned from tainted data (repeat until stable)
    for _ in range(5):
        before = len(taint.tainted)
        for var in function["vars"]:
            init = var.get("init")
            if init:
                reason = taint.reason_for_arg(init, direct_sources)
                if reason:
                    taint.add(var["usr"] or var["name"], reason)
        for assignment in function["assignments"]:
            reason = taint.reason_for_arg(assignment["value"], direct_sources)
            if reason:
                taint.add(assignment["target_usr"] or assignment["target"], reason)
        if len(taint.tainted) == before:
            break
    return taint, direct_sources
