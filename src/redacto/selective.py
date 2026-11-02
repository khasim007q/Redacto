"""Bounded, exact-passage redaction offers for mixed-source records.

An offer is keyed matching material, never a claim of semantic equivalence.
Source-derived passages require review before edits; uncertain paraphrases stay
visible to the independent survivor assessment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from redacto.discovery.normalization import fingerprint

MAX_SOURCE_PASSAGES = 128
MAX_SPANS = 32
MIN_PASSAGE_WORDS = 8
MIN_PASSAGE_CHARS = 32
MIN_RETAINED_WORDS = 8
# Window hashing is proportional to both record and passage length. Avoid offers
# whose later apply would need unbounded work even within the record byte cap.
MAX_HASH_CHAR_WORK = 32_000_000


@dataclass(frozen=True)
class RedactionOffer:
    spans: list[dict]
    matched_bytes: int
    retained_bytes: int


def passage_offer(source: str, content: str, key: str, *, max_bytes: int) -> RedactionOffer | None:
    if not content or len(content.encode("utf-8")) > max_bytes:
        return None
    passages = [source.strip(), *re.split(r"(?<=[.!?])\s+|\n+", source)]
    forms: dict[tuple[str, int], dict] = {}
    intervals = set()
    for passage in list(dict.fromkeys(passages))[:MAX_SOURCE_PASSAGES]:
        words = passage.strip().split()
        if len(words) < MIN_PASSAGE_WORDS or len(passage.strip()) < MIN_PASSAGE_CHARS:
            continue
        if len(passage) > len(content) * 2:
            continue
        pattern = r"\s+".join(re.escape(word) for word in words)
        if words[0][0].isalnum():
            pattern = r"(?<!\w)" + pattern
        if words[-1][-1].isalnum():
            pattern += r"(?!\w)"
        for match in re.finditer(pattern, content, re.IGNORECASE):
            text = match.group(0)
            digest = fingerprint(text, key)
            forms[(digest, len(text))] = {"hmac": digest, "length": len(text)}
            if len(forms) > MAX_SPANS:
                return None
            intervals.add(match.span())
    if not intervals:
        return None
    if sum(length * max(0, len(content) - length + 1) for length in {form[1] for form in forms}) > MAX_HASH_CHAR_WORK:
        return None
    merged: list[list[int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    remaining, cursor = [], 0
    matched_bytes = 0
    for start, end in merged:
        remaining.append(content[cursor:start])
        matched_bytes += len(content[start:end].encode("utf-8"))
        cursor = end
    remaining.append(content[cursor:])
    retained = " ".join(remaining)
    if len(re.findall(r"\w+", retained)) < MIN_RETAINED_WORDS:
        return None
    return RedactionOffer(list(forms.values()), matched_bytes, len(retained.encode("utf-8")))
