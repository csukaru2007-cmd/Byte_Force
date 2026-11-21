"""Chip profiles and board lookup.

Only profiles that were built from Espressif documentation are offered as supported.
Other ESP32 family members are listed so that the user gets a clear "no verified
profile yet" message instead of silently being checked against the wrong chip.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache

from backend.config import DATABASES

PROFILE_FILES = {"esp32_wroom_32": "esp32_wroom_32.json"}
UNSUPPORTED_FAMILIES = {
    "esp32s2": "ESP32-S2", "esp32s3": "ESP32-S3", "esp32c3": "ESP32-C3", "esp32c6": "ESP32-C6", "esp32h2": "ESP32-H2",
}
_MCU_ID = {"ESP32": "esp32", "ESP32S2": "esp32s2", "ESP32S3": "esp32s3", "ESP32C3": "esp32c3", "ESP32C6": "esp32c6"}


class ProfileError(ValueError):
    pass


def _norm(text: str) -> str:
    return re.sub(r"[\s_\-]+", "", text.strip().lower())


@lru_cache(maxsize=None)
def load_profile(profile_id: str) -> dict:
    try:
        return json.loads((DATABASES / PROFILE_FILES[profile_id]).read_text(encoding="utf-8"))
    except KeyError:
        raise ProfileError(f"unknown profile id {profile_id!r}") from None


@lru_cache(maxsize=1)
def _boards() -> dict:
    return json.loads((DATABASES / "board_profiles.json").read_text(encoding="utf-8"))


def board_info(board_id: str | None) -> dict | None:
    if not board_id:
        return None
    info = _boards()["boards"].get(board_id.strip())
    return {"id": board_id.strip(), **info} if info else None


def resolve_profile(selection: str) -> str:
    """Map a user selection ("ESP32-WROOM-32", "esp32", ...) to a profile id or raise ProfileError."""
    wanted = _norm(selection)
    for profile_id in PROFILE_FILES:
        profile = load_profile(profile_id)
        if wanted in {_norm(a) for a in [profile_id, *profile["aliases"]]}:
            return profile_id
    for family_id, name in UNSUPPORTED_FAMILIES.items():
        if wanted in (_norm(family_id), _norm(name)):
            raise ProfileError(f"No verified hardware profile for {name} yet; only the original ESP32 "
                               "(ESP32-WROOM-32) is supported. Hardware checks were skipped.")
    raise ProfileError(f"Unknown chip profile '{selection}'. Hardware checks were skipped.")


def profile_for_mcu(mcu: str | None) -> str | None:
    if not mcu:
        return None
    return _boards()["mcu_to_profile"].get(mcu)


def mcu_family_id(mcu: str | None) -> str | None:
    return _MCU_ID.get(mcu or "")


def list_profiles() -> list[dict]:
    profiles = []
    for profile_id in PROFILE_FILES:
        p = load_profile(profile_id)
        profiles.append({"id": profile_id, "name": p["display_name"], "module": p["module"], "supported": True,
                         "source": p["sources"][0]["title"] + " " + p["sources"][0]["version"]})
    for family_id, name in UNSUPPORTED_FAMILIES.items():
        profiles.append({"id": family_id, "name": name, "supported": False,
                         "note": "No verified profile yet; hardware checks will be skipped."})
    return profiles
