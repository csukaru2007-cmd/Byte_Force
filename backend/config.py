"""Central configuration. Every value can be overridden with an environment variable."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATABASES = ROOT / "databases"
FRONTEND = ROOT / "frontend"
SAMPLES = ROOT / "samples"
STUB_HEADERS = Path(__file__).resolve().parent / "ast_engine" / "stubs"


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


# Registry metadata cache (one JSON file per request URL)
CACHE_DIR = Path(os.environ.get("SHIPSAFE_CACHE_DIR", ROOT / ".shipsafe_cache"))
CACHE_TTL_SECONDS = _int("SHIPSAFE_CACHE_TTL", 24 * 3600)

# Where uploaded projects are extracted (one temporary folder per scan, deleted afterwards)
SCAN_WORK_DIR = Path(os.environ.get("SHIPSAFE_SCAN_DIR", ROOT / ".shipsafe_scans"))

# Upload / extraction limits
MAX_UPLOAD_BYTES = _int("SHIPSAFE_MAX_UPLOAD_MB", 25) * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = _int("SHIPSAFE_MAX_UNCOMPRESSED_MB", 200) * 1024 * 1024
MAX_ARCHIVE_ENTRIES = _int("SHIPSAFE_MAX_ENTRIES", 5000)
MAX_COMPRESSION_RATIO = _int("SHIPSAFE_MAX_RATIO", 200)

# Registry HTTP behaviour
REGISTRY_API = os.environ.get("SHIPSAFE_REGISTRY_API", "https://api.registry.platformio.org/v3")
REGISTRY_CONNECT_TIMEOUT = 5
REGISTRY_READ_TIMEOUT = 15
REGISTRY_MAX_RETRIES = 2          # retries after HTTP 429 / 503
REGISTRY_MAX_RETRY_WAIT = 10      # seconds; longer Retry-After values are not waited for

# AST analysis limits
MAX_SOURCE_FILES = _int("SHIPSAFE_MAX_SOURCE_FILES", 400)
MAX_SOURCE_FILE_BYTES = _int("SHIPSAFE_MAX_SOURCE_KB", 1024) * 1024
SCAN_TIME_LIMIT_SECONDS = _int("SHIPSAFE_SCAN_TIME_LIMIT", 300)

# How many finished scans are kept in memory for GET /api/scan/{id}
MAX_STORED_SCANS = _int("SHIPSAFE_MAX_STORED_SCANS", 50)
