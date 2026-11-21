"""Package-name similarity against the trusted package database.

A similarity score is evidence for a human, never a verdict. The relation types are:

  exact        same name after normalisation (case, spaces, '_', '-', '.', trailing "library")
  confusable   identical after mapping look-alike characters (0/o, 1/l/i, rn/m, vv/w, 5/s, 3/e)
  edit         a small number of character edits (Damerau-Levenshtein): substitution,
               insertion, deletion or swap of adjacent characters
  extra_words  the trusted name's words are all present, plus one or two extra words
  missing_words  the name is the trusted name with one word removed

Calibration (see scripts/calibrate_similarity.py and docs/ARCHITECTURE.md) showed that
model-number variants (BME280 vs BME680 vs BMP280) are real, distinct, legitimate
packages that are within one edit of each other. Therefore the package-intelligence
step does not report an 'edit' match when the candidate's publisher is the verified
publisher of the trusted package, and it never labels a package malicious.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from rapidfuzz import fuzz
from rapidfuzz.distance import DamerauLevenshtein

_SEPARATORS = re.compile(r"[\s_\-.]+")
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_TRAILING_GENERIC = ("library", "lib")
_CONFUSABLES = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("i", "l"), ("5", "s"), ("3", "e")]


def tokens(name: str) -> list[str]:
    words = []
    for part in _SEPARATORS.split(name.strip()):
        words.extend(w.lower() for w in _CAMEL.split(part) if w)
    while len(words) > 1 and words[-1] in _TRAILING_GENERIC:
        words.pop()
    return words


def words(name: str) -> list[str]:
    """Separator-delimited words ('Adafruit NeoPixel' -> ['adafruit', 'neopixel'])."""
    parts = [w.lower() for w in _SEPARATORS.split(name.strip()) if w]
    while len(parts) > 1 and parts[-1] in _TRAILING_GENERIC:
        parts.pop()
    return parts


def compact(name: str) -> str:
    return "".join(tokens(name))


def skeleton(text: str) -> str:
    text = text.lower()
    for source, target in _CONFUSABLES:
        text = text.replace(source, target)
    return text


def max_edits(length: int) -> int:
    if length < 5:
        return 0          # too short: one edit turns almost anything into anything
    return 1 if length <= 8 else 2


def describe_difference(candidate: str, trusted: str) -> str:
    """Human-readable list of edits that turn `trusted` into `candidate` (normalised forms)."""
    a, b = compact(trusted), compact(candidate)
    if a == b:
        if candidate == trusted:
            return "identical name"
        return "same name after normalising case and separators"
    changes = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op == "replace":
            changes.append(f"'{a[i1:i2]}' replaced by '{b[j1:j2]}'")
        elif op == "delete":
            changes.append(f"'{a[i1:i2]}' removed")
        elif op == "insert":
            changes.append(f"'{b[j1:j2]}' added")
    return "; ".join(changes)


@dataclass
class SimilarityMatch:
    candidate: str
    trusted_name: str            # canonical name of the trusted package
    matched_alias: str           # the canonical name or alias that matched
    relation: str
    similarity_score: float      # rapidfuzz normalised similarity of the normalised names, 0..1
    token_similarity: float
    edit_distance: int
    difference: str
    trusted_entry: dict = field(repr=False, default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "candidate": self.candidate, "matched_trusted_package": self.trusted_name,
            "matched_alias": self.matched_alias, "relation": self.relation,
            "similarity_score": self.similarity_score, "token_similarity": self.token_similarity,
            "edit_distance": self.edit_distance, "difference": self.difference,
        }


_RELATION_PRIORITY = {"exact": 0, "confusable": 1, "edit": 2, "extra_words": 3, "missing_words": 4}


def compare(candidate: str, trusted_name: str) -> tuple[str | None, float, float, int]:
    """Return (relation or None, similarity, token_similarity, edit_distance)."""
    a, b = compact(candidate), compact(trusted_name)
    if not a or not b:
        return None, 0.0, 0.0, max(len(a), len(b))
    score = round(fuzz.ratio(a, b) / 100, 3)
    ta, tb = tokens(candidate), tokens(trusted_name)
    token_score = round(fuzz.token_set_ratio(" ".join(ta), " ".join(tb)) / 100, 3)
    distance = DamerauLevenshtein.distance(a, b)
    if a == b:
        return "exact", score, token_score, distance
    if skeleton(a) == skeleton(b):
        return "confusable", score, token_score, distance
    if distance <= max_edits(min(len(a), len(b))):
        return "edit", score, token_score, distance
    # Calibration: allowing any extra word matched 82 legitimate extension libraries
    # ("FastLED NeoMatrix", "U8g2_for_Adafruit_GFX"). Only a short affix (<= 3 chars)
    # glued to the complete trusted name is treated as a look-alike (e.g. "ArduinoJsonPro").
    if len(b) >= 6 and (a.startswith(b) or a.endswith(b)) and 0 < len(a) - len(b) <= 3:
        return "extra_words", score, token_score, distance
    # One whole word dropped from a name of three or more real words
    # (separator-delimited, so "NeoPixel" counts as one word, not two).
    wa, wb = set(words(candidate)), set(words(trusted_name))
    if len(a) >= 6 and len(wb) >= 3 and wa < wb and len(wb - wa) == 1:
        return "missing_words", score, token_score, distance
    return None, score, token_score, distance


def best_match(candidate: str, trusted_packages: list[dict]) -> SimilarityMatch | None:
    """Closest trusted package by relation type, then by similarity score."""
    best: SimilarityMatch | None = None
    for entry in trusted_packages:
        for alias in [entry["canonical_name"], *entry.get("aliases", [])]:
            relation, score, token_score, distance = compare(candidate, alias)
            if relation is None:
                continue
            match = SimilarityMatch(candidate, entry["canonical_name"], alias, relation, score,
                                    token_score, distance, describe_difference(candidate, alias), entry)
            if best is None or (_RELATION_PRIORITY[relation], -score) < \
                    (_RELATION_PRIORITY[best.relation], -best.similarity_score):
                best = match
    return best
