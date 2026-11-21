"""Extract and classify the dependencies of a PlatformIO project.

Reads (never executes):
  * platformio.ini (+ files listed in [platformio] extra_configs inside the project)
  * lib/ private libraries
  * .pio/libdeps/<env>/ installed packages (.piopm, library.json, library.properties)

Every entry is classified so that the package-intelligence step only asks the
registry about things that actually live in the registry:

  kind                 field              meaning
  -------------------  -----------------  ------------------------------------------------
  registry_library     lib_deps           [owner/]name[@version] resolved by the registry
  registry_legacy_id   lib_deps           numeric registry ID (old PlatformIO syntax)
  framework_builtin    lib_deps           library bundled with the Arduino-ESP32 framework
  git                  lib_deps/...       git repository URL (optionally #ref)
  archive_url          lib_deps/...       downloadable archive URL
  local                lib_deps / lib/    local folder, file:// or symlink://
  platform             platform           development platform (e.g. espressif32)
  tool_package         platform_packages  toolchain / tool / framework package override
  framework            framework          framework name (arduino, espidf)
"""

from __future__ import annotations

import configparser
import json
import re
import shlex
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from backend.config import DATABASES

ARCHIVE_EXTENSIONS = (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")
GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}
_REPO_PATH = re.compile(r"^/?([^/]+)/([^/#?]+?)(?:\.git)?/?$")
_SCP_GIT = re.compile(r"^git@([^:]+):([^/]+)/([^#]+?)(?:\.git)?(?:#(.*))?$")


@dataclass
class Dependency:
    raw: str
    field: str
    kind: str
    name: str
    owner: str | None = None
    version_spec: str | None = None
    source: str = "registry"          # registry | git | archive | local | builtin
    url: str | None = None
    git_ref: str | None = None
    git_pin: str | None = None        # commit | tag | branch_or_tag | unpinned
    repo_host: str | None = None
    repo_owner: str | None = None
    repo_name: str | None = None
    custom_name: str | None = None
    registry_type: str | None = None  # library | platform | tool (only for registry lookups)
    declared_in: list[str] = field(default_factory=list)
    declared: bool = True             # False => only found installed in .pio/libdeps (transitive)
    installed: dict | None = None

    @property
    def key(self) -> tuple:
        return (self.field, (self.owner or "").lower(), self.name.lower(), self.url or "")

    @property
    def display_name(self) -> str:
        return f"{self.owner}/{self.name}" if self.owner else self.name

    def to_dict(self) -> dict:
        data = asdict(self)
        data["display_name"] = self.display_name
        return data


@dataclass
class EnvironmentInfo:
    name: str
    platform: str | None
    board: str | None
    framework: list[str]
    build_flags: list[str]
    defines: dict[str, str | None]
    include_dirs: list[str]
    ignored_build_flags: list[str]
    extra_scripts: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DependencyExtraction:
    environments: list[EnvironmentInfo]
    default_envs: list[str]
    dependencies: list[Dependency]
    notes: list[str] = field(default_factory=list)       # things the user should know

    def to_dict(self) -> dict:
        return {
            "environments": [e.to_dict() for e in self.environments],
            "default_envs": self.default_envs,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "notes": self.notes,
        }


@lru_cache(maxsize=1)
def framework_builtin_names() -> frozenset[str]:
    data = json.loads((DATABASES / "framework_libraries.json").read_text(encoding="utf-8"))
    return frozenset(n.lower() for n in data["libraries_3x"] + data["libraries_2x"])


# --------------------------------------------------------------------------- spec parsing

def _is_local_path(text: str) -> bool:
    return (text.startswith(("file://", "symlink://", "./", "../", "~/", "/", ".\\", "..\\"))
            or bool(re.match(r"^[A-Za-z]:[\\/]", text)))


def _looks_like_source(text: str) -> bool:
    return "://" in text or text.startswith("git@") or _is_local_path(text)


def git_pin_kind(ref: str | None) -> str:
    if not ref:
        return "unpinned"
    if re.fullmatch(r"[0-9a-fA-F]{7,40}", ref):
        return "commit"
    if re.fullmatch(r"v?\d+(\.\d+){0,3}([-.+][\w.]+)?", ref):
        return "tag"
    return "branch_or_tag"


def classify_source(text: str) -> dict:
    """Classify a URL or path. Returns kind/source plus repository identity when known."""
    text = text.strip()
    result: dict = {"url": text}
    if _is_local_path(text):
        return {**result, "kind": "local", "source": "local"}

    scp = _SCP_GIT.match(text)
    if scp:
        host, owner, repo, ref = scp.groups()
        return {**result, "kind": "git", "source": "git", "repo_host": host.lower(),
                "repo_owner": owner, "repo_name": repo, "git_ref": ref, "git_pin": git_pin_kind(ref)}

    url_part, _, ref = text.partition("#")
    ref = ref or None
    clean = url_part[4:] if url_part.startswith("git+") else url_part
    parsed = urlparse(clean)
    host = (parsed.hostname or "").lower()
    path_lower = parsed.path.lower()
    is_git = (url_part.startswith(("git+", "ssh://")) or path_lower.endswith(".git")
              or (host in GIT_HOSTS and not path_lower.endswith(ARCHIVE_EXTENSIONS)
                  and "/archive/" not in path_lower and "/releases/download/" not in path_lower))
    repo = _REPO_PATH.match(parsed.path) if host in GIT_HOSTS or is_git else None
    identity = {"repo_host": host or None}
    if repo:
        identity.update(repo_owner=repo.group(1), repo_name=repo.group(2))
    if is_git:
        return {**result, **identity, "kind": "git", "source": "git",
                "git_ref": ref, "git_pin": git_pin_kind(ref)}
    return {**result, **identity, "kind": "archive_url", "source": "archive"}


def _split_owner_name_version(text: str) -> tuple[str | None, str, str | None]:
    """'owner/Name @ ^1.2' -> ('owner', 'Name', '^1.2')."""
    version = None
    if "@" in text:
        text, version = text.split("@", 1)
        version = version.strip() or None
    text = text.strip()
    owner = None
    if "/" in text:
        owner, text = text.split("/", 1)
        owner = owner.strip() or None
    return owner, text.strip(), version


def parse_spec(raw: str, field_name: str) -> Dependency:
    """Parse one package specification as written in platformio.ini."""
    text = raw.strip()
    registry_type = {"lib_deps": "library", "platform": "platform", "platform_packages": "tool"}[field_name]

    # "CustomName=<source>" (lib_deps) - keep the custom name for reporting
    custom_name = None
    if "=" in text:
        left, right = text.split("=", 1)
        if "://" not in left and _looks_like_source(right.strip()):
            custom_name, text = left.strip(), right.strip()

    # "[owner/]name @ <source>" (common in platform_packages)
    named_source = re.match(r"^([^\s@:]+(?:/[^\s@:]+)?)\s*@\s*(\S.*)$", text)
    if named_source and _looks_like_source(named_source.group(2).strip()):
        owner, name, _ = _split_owner_name_version(named_source.group(1))
        info = classify_source(named_source.group(2).strip())
        return _dependency_from_source(raw, field_name, info, name=name, owner=owner,
                                       custom_name=custom_name)

    if _looks_like_source(text):
        info = classify_source(text)
        name = custom_name or info.get("repo_name") or Path(urlparse(text).path).name or text
        return _dependency_from_source(raw, field_name, info, name=name, custom_name=custom_name)

    if field_name == "lib_deps" and re.fullmatch(r"\d+(@.*)?", text):
        ident, _, version = text.partition("@")
        return Dependency(raw=raw, field=field_name, kind="registry_legacy_id", name=ident,
                          version_spec=version or None, source="registry", registry_type="library")

    owner, name, version = _split_owner_name_version(text)
    if field_name == "lib_deps":
        if owner is None and name.lower() in framework_builtin_names():
            return Dependency(raw=raw, field=field_name, kind="framework_builtin", name=name,
                              version_spec=version, source="builtin")
        kind = "registry_library"
    else:
        kind = "platform" if field_name == "platform" else "tool_package"
    return Dependency(raw=raw, field=field_name, kind=kind, name=name, owner=owner,
                      version_spec=version, source="registry", registry_type=registry_type)


def _dependency_from_source(raw, field_name, info, *, name, owner=None, custom_name=None) -> Dependency:
    kind = info["kind"]
    if field_name == "platform":
        kind = "platform"
    elif field_name == "platform_packages":
        kind = "tool_package"
    return Dependency(
        raw=raw, field=field_name, kind=kind, name=name, owner=owner, source=info["source"],
        url=info.get("url"), git_ref=info.get("git_ref"), git_pin=info.get("git_pin"),
        repo_host=info.get("repo_host"), repo_owner=info.get("repo_owner"),
        repo_name=info.get("repo_name"), custom_name=custom_name,
    )


def split_entries(value: str) -> list[str]:
    """Multi-line and/or comma-separated values, with ; comments removed."""
    entries = []
    for line in value.splitlines():
        line = re.split(r"(?:^|\s);", line, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        # PlatformIO separates entries with ", " (comma + space); a range like ">=1.0,<2" has no space
        entries.extend(p.strip() for p in re.split(r",\s+", line) if p.strip())
    return entries


# --------------------------------------------------------------------------- ini handling

class PlatformIOConfig:
    def __init__(self, root: Path):
        self.root = root
        self.parser = configparser.ConfigParser(
            interpolation=None, inline_comment_prefixes=(";",), strict=False,
            comment_prefixes=("#", ";"), empty_lines_in_values=False)
        self.parser.optionxform = str.lower
        self.unresolved_references: set[str] = set()
        ini = root / "platformio.ini"
        self.parser.read(ini, encoding="utf-8")
        extras = self._raw("platformio", "extra_configs")
        for pattern in split_entries(extras or ""):
            for path in sorted(root.glob(pattern)):
                if path.resolve().is_relative_to(root.resolve()) and path.is_file():
                    self.parser.read(path, encoding="utf-8")

    def _raw(self, section: str, option: str) -> str | None:
        if self.parser.has_option(section, option):
            return self.parser.get(section, option)
        return None

    @property
    def env_names(self) -> list[str]:
        return [s.split(":", 1)[1] for s in self.parser.sections() if s.startswith("env:")]

    @property
    def default_envs(self) -> list[str]:
        return split_entries(self._raw("platformio", "default_envs") or "")

    def _chain(self, env: str) -> list[str]:
        """Sections consulted for an option of env:<env>, in priority order."""
        order: list[str] = []

        def visit(section: str, depth: int = 0) -> None:
            if section in order or depth > 10 or not self.parser.has_section(section):
                return
            order.append(section)
            for parent in split_entries(self._raw(section, "extends") or ""):
                visit(parent, depth + 1)

        visit(f"env:{env}")
        if self.parser.has_section("env") and "env" not in order:
            order.append("env")
        return order

    def option(self, env: str, option: str) -> str | None:
        for section in self._chain(env):
            value = self._raw(section, option)
            if value is not None:
                return self.expand(value, env)
        return None

    def expand(self, value: str, env: str, depth: int = 0) -> str:
        def replace(match: re.Match) -> str:
            ref = match.group(1)
            section, _, option = ref.rpartition(".")
            if depth > 8:
                self.unresolved_references.add(ref)
                return ""
            if section == "this":
                if option == "__env__":
                    return env
                found = self.option(env, option)
            elif section == "sysenv":
                # Environment variables of the uploader's machine are unknown; never read ours.
                self.unresolved_references.add(ref)
                return ""
            else:
                found = self._raw(section, option)
                found = self.expand(found, env, depth + 1) if found is not None else None
            if found is None:
                self.unresolved_references.add(ref)
                return ""
            return found

        return re.sub(r"\$\{([^}]+)\}", replace, value)


def parse_build_flags(flags: list[str]) -> tuple[dict[str, str | None], list[str], list[str], list[str]]:
    """Return (defines, include_dirs, ignored_flags, dynamic_flags). Nothing is executed."""
    defines: dict[str, str | None] = {}
    includes: list[str] = []
    ignored: list[str] = []
    dynamic: list[str] = []
    for line in flags:
        if line.startswith("!"):
            dynamic.append(line)        # PlatformIO would run this as a shell command: never do that
            continue
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError:
            ignored.append(line)
            continue
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token in ("-D", "-I") and i + 1 < len(tokens):
                token, i = token + tokens[i + 1], i + 1
            if token.startswith("-D"):
                name, eq, val = token[2:].partition("=")
                if name:
                    defines[name] = val if eq else None
            elif token.startswith("-I"):
                includes.append(token[2:])
            else:
                ignored.append(token)
            i += 1
    return defines, includes, ignored, dynamic


# --------------------------------------------------------------------------- installed packages

def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _read_properties(path: Path) -> dict:
    data = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                data[key.strip()] = value.strip()
    except OSError:
        pass
    return data


def read_installed_package(folder: Path) -> dict:
    """Metadata of one installed package folder, from the files PlatformIO leaves behind."""
    info: dict = {"folder": folder.name, "metadata_files": []}
    piopm = _read_json(folder / ".piopm")
    if piopm:
        info["metadata_files"].append(".piopm")
        spec = piopm.get("spec") or {}
        info.update(name=piopm.get("name"), version=piopm.get("version"),
                    owner=spec.get("owner"), registry_id=spec.get("id"),
                    requirements=spec.get("requirements"), uri=spec.get("uri"))
    manifest = _read_json(folder / "library.json")
    if manifest:
        info["metadata_files"].append("library.json")
        repository = manifest.get("repository")
        info.setdefault("name", manifest.get("name"))
        info.setdefault("version", manifest.get("version"))
        info["manifest_repository"] = repository.get("url") if isinstance(repository, dict) else None
    properties = _read_properties(folder / "library.properties")
    if properties:
        info["metadata_files"].append("library.properties")
        if not info.get("name"):
            info["name"] = properties.get("name")
        if not info.get("version"):
            info["version"] = properties.get("version")
        info["manifest_url"] = properties.get("url")
    info["name"] = info.get("name") or folder.name
    return info


def installed_packages(root: Path) -> dict[str, list[dict]]:
    """{env_name: [installed package info]} from .pio/libdeps."""
    libdeps = root / ".pio" / "libdeps"
    result: dict[str, list[dict]] = {}
    if not libdeps.is_dir():
        return result
    for env_dir in sorted(p for p in libdeps.iterdir() if p.is_dir()):
        packages = []
        for folder in sorted(p for p in env_dir.iterdir() if p.is_dir()):
            info = read_installed_package(folder)
            info["path"] = folder.relative_to(root).as_posix()
            packages.append(info)
        result[env_dir.name] = packages
    return result


# --------------------------------------------------------------------------- main entry point

def extract_dependencies(root: Path) -> DependencyExtraction:
    cfg = PlatformIOConfig(root)
    notes: list[str] = []
    environments: list[EnvironmentInfo] = []
    deps: dict[tuple, Dependency] = {}

    def add(dep: Dependency, env: str) -> None:
        existing = deps.get(dep.key)
        if existing:
            if env not in existing.declared_in:
                existing.declared_in.append(env)
        else:
            dep.declared_in = [env]
            deps[dep.key] = dep

    env_names = cfg.env_names
    if not env_names:
        notes.append("platformio.ini defines no [env:...] section; no build environment to analyse.")
    for env in env_names:
        build_flags = split_entries(cfg.option(env, "build_flags") or "")
        defines, includes, ignored, dynamic = parse_build_flags(build_flags)
        extra_scripts = split_entries(cfg.option(env, "extra_scripts") or "")
        if dynamic:
            notes.append(f"[env:{env}] has dynamic build flags ({len(dynamic)}) that PlatformIO would "
                         "execute; ShipSafe did not run them.")
        if extra_scripts:
            notes.append(f"[env:{env}] declares extra_scripts {extra_scripts}; ShipSafe never executes "
                         "project build scripts.")
        environments.append(EnvironmentInfo(
            name=env, platform=cfg.option(env, "platform"), board=cfg.option(env, "board"),
            framework=[f.strip(",") for f in split_entries(cfg.option(env, "framework") or "")],
            build_flags=build_flags, defines=defines, include_dirs=includes,
            ignored_build_flags=ignored, extra_scripts=extra_scripts,
        ))
        for entry in split_entries(cfg.option(env, "lib_deps") or ""):
            add(parse_spec(entry, "lib_deps"), env)
        platform = cfg.option(env, "platform")
        if platform:
            add(parse_spec(platform.strip(), "platform"), env)
        for entry in split_entries(cfg.option(env, "platform_packages") or ""):
            add(parse_spec(entry, "platform_packages"), env)
        for name in environments[-1].framework:
            add(Dependency(raw=name, field="framework", kind="framework", name=name, source="builtin"), env)

    # Private libraries in lib/ are local dependencies
    lib_dir = root / "lib"
    if lib_dir.is_dir():
        for folder in sorted(p for p in lib_dir.iterdir() if p.is_dir()):
            dep = Dependency(raw=f"lib/{folder.name}", field="lib_dir", kind="local",
                             name=folder.name, source="local", url=f"lib/{folder.name}")
            add(dep, "*")

    # Resolved packages installed in .pio/libdeps (when the archive includes them)
    for env, packages in installed_packages(root).items():
        for package in packages:
            match = _match_installed(package, deps.values())
            if match:
                match.installed = package
            else:
                dep = Dependency(raw=package["path"], field="installed", kind="registry_library"
                                 if package.get("owner") else "local", name=package["name"],
                                 owner=package.get("owner"), version_spec=package.get("version"),
                                 source="registry" if package.get("owner") else "local",
                                 registry_type="library" if package.get("owner") else None,
                                 declared=False, installed=package)
                add(dep, env)
        notes.append(f".pio/libdeps/{env} found: {len(packages)} installed package(s) inspected.")

    if cfg.unresolved_references:
        notes.append("Unresolved ${...} references in platformio.ini (left empty): "
                     + ", ".join(sorted(cfg.unresolved_references)))
    return DependencyExtraction(environments, cfg.default_envs, list(deps.values()), notes)


def _match_installed(package: dict, deps) -> Dependency | None:
    """Attach an installed package to its lib_deps entry: same name, same owner preferred.

    A name match with a *different* owner is still attached, so that the package step can
    report the mismatch (PKG010) instead of silently treating it as a transitive dependency.
    """
    name = (package.get("name") or "").lower()
    folder = package.get("folder", "").lower()
    owner = (package.get("owner") or "").lower()
    name_matches = []
    for dep in deps:
        if dep.field != "lib_deps":
            continue
        candidates = {dep.name.lower(), (dep.custom_name or "").lower(), (dep.repo_name or "").lower()}
        if name in candidates or folder in candidates:
            if not dep.owner or not owner or dep.owner.lower() == owner:
                return dep
            name_matches.append(dep)
    return name_matches[0] if name_matches else None
