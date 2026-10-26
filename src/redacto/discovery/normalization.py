"""Content normalization and keyed fingerprints.

Fingerprints use HMAC-SHA256 with a configured key. Plain hashes are never used
for low-entropy secrets because they are trivially reversible by guessing.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata

_WHITESPACE = re.compile(r"\s+")
_PUNCT = re.compile(r"[^\w\s]")
_ZERO_WIDTH = re.compile(r"[\u200b-\u200d\ufeff]")


def normalize_whitespace(text: str) -> str:
    return _WHITESPACE.sub(" ", _ZERO_WIDTH.sub("", text)).strip()


def normalize_loose(text: str) -> str:
    """Aggressive normalization used for matching and fingerprints.

    Casefold, unicode NFKC, strip zero-width characters, drop punctuation and
    collapse whitespace. Deliberately still reversible-free: no stemming.
    """
    folded = unicodedata.normalize("NFKC", text).casefold()
    folded = _ZERO_WIDTH.sub("", folded)
    folded = _PUNCT.sub("", folded)
    return _WHITESPACE.sub(" ", folded).strip()


def variants(text: str) -> set[str]:
    """Bounded variant set for exact/normalized discovery."""
    raw = text.strip()
    return {
        raw,
        normalize_whitespace(raw),
        normalize_loose(raw),
    }


def fingerprint(text: str, key: str) -> str:
    normalized = normalize_loose(text)
    digest = hmac.new(key.encode("utf-8"), normalized.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()
