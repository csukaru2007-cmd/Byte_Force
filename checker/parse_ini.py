"""Read the lib_deps entries out of a platformio.ini file.

PlatformIO lets you write a dependency in several ways. We understand these:

    bblanchon/ArduinoJson@7.4.3          owner / name @ version
    bblanchon/ArduinoJson                owner / name, no version
    ArduinoJson@^7.0.0                   bare name with a version range
    ArduinoJson                          bare name only
    Adafruit NeoPixel                    names may contain spaces
    https://github.com/owner/repo.git#v1.2.0     a GitHub URL (optionally with #tag)
    MyLib=https://github.com/owner/repo.git      a URL with a custom name in front

lib_deps can be written one per line or comma-separated, and can live in [env]
or any [env:...] section. ${section.option} references are expanded.
"""

import configparser
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Dependency:
    """One line from lib_deps, split into its parts."""

    raw: str                    # the line exactly as written in platformio.ini
    kind: str                   # "registry", "github" or "other" (local path, other URL...)
    owner: str | None = None    # "bblanchon" (None if the line has no owner)
    name: str = ""              # "ArduinoJson"
    version: str | None = None  # "7.4.3", "^7.0.0" or None
    url: str | None = None      # the URL for github / other dependencies
    section: str = ""           # which [env:...] section it came from


# https://github.com/<owner>/<repo>(.git)(#ref)
GITHUB_URL = re.compile(r"github\.com[/:]([^/\s]+)/([^/#\s]+?)(?:\.git)?/?(?:#(.+))?$", re.IGNORECASE)


def read_ini(path: Path) -> configparser.ConfigParser:
    """Load platformio.ini. Interpolation is off because PlatformIO uses its own ${...} syntax."""
    parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";",), strict=False)
    parser.read(path, encoding="utf-8")
    return parser


def expand_references(value: str, parser: configparser.ConfigParser, depth: int = 0) -> str:
    """Replace ${section.option} (e.g. ${common.lib_deps}) with that option's value."""

    def replace(match: re.Match) -> str:
        section, _, option = match.group(1).rpartition(".")
        if parser.has_option(section, option) and depth < 5:
            return expand_references(parser.get(section, option), parser, depth + 1)
        return ""  # unknown reference, e.g. ${platformio.packages_dir}: nothing to check

    return re.sub(r"\$\{([^}]+)\}", replace, value)


def split_entries(value: str) -> list[str]:
    """lib_deps can be one entry per line or comma-separated; return clean entries."""
    entries = []
    for line in value.splitlines():
        line = line.split(";")[0].strip()          # drop ; comments
        for part in line.split(","):
            part = part.strip()
            if part:
                entries.append(part)
    return entries


def parse_entry(raw: str, section: str = "") -> Dependency:
    """Turn one lib_deps entry into a Dependency."""
    text = raw.strip()

    # "CustomName=https://..." -> keep only the URL part
    if "=" in text and "://" in text.split("=", 1)[1]:
        text = text.split("=", 1)[1].strip()

    # URLs (GitHub or anything else)
    if "://" in text or text.startswith("git@"):
        match = GITHUB_URL.search(text)
        if match:
            owner, repo, ref = match.groups()
            return Dependency(raw=raw, kind="github", owner=owner, name=repo, version=ref, url=text, section=section)
        return Dependency(raw=raw, kind="other", name=text, url=text, section=section)

    # Local folders: file://, symlink:// are caught above; plain paths look like this
    if text.startswith((".", "/", "~")) or re.match(r"^[A-Za-z]:\\", text):
        return Dependency(raw=raw, kind="other", name=text, url=text, section=section)

    # Registry form: [owner/]name[@version]
    version = None
    if "@" in text:
        text, version = text.split("@", 1)
        version = version.strip() or None
    owner = None
    if "/" in text:
        owner, text = text.split("/", 1)
        owner = owner.strip()
    return Dependency(raw=raw, kind="registry", owner=owner, name=text.strip(), version=version, section=section)


def parse_platformio_ini(path: Path) -> list[Dependency]:
    """Return every lib_deps entry in the file (duplicates across envs are kept once)."""
    parser = read_ini(path)
    deps: list[Dependency] = []
    seen: set[str] = set()
    for section in parser.sections():
        if not parser.has_option(section, "lib_deps"):
            continue
        value = expand_references(parser.get(section, "lib_deps"), parser)
        for entry in split_entries(value):
            if entry.lower() in seen:
                continue
            seen.add(entry.lower())
            deps.append(parse_entry(entry, section))
    return deps
