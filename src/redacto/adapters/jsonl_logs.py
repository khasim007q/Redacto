"""JSONL log adapter: one synthetic event per line.

Event identity is stable even when a line has no `event_id`: a keyed hash of the
line is used. Deletes match that identity (and prefer the recorded line index), so
duplicate or malformed lines cannot make Redacto delete the wrong event.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Callable, Iterable, Sequence

from redacto.adapters.base import (
    AdapterError,
    Capabilities,
    Record,
    StoreAdapter,
    leftover_rewrite_temps,
    redact_spans,
    rewrite_temp_prefix,
)
from redacto.discovery.normalization import fingerprint



class _LogChanged(Exception):
    """The log was rewritten (not just appended to) while an edit was prepared."""

class JsonlLogAdapter(StoreAdapter):
    adapter_id = "jsonl_logs"
    store_id = "jsonl_logs"

    def __init__(self, path: Path, hmac_key: str = "dev-only-synthetic-fixture-key"):
        self._path = path.expanduser().resolve()
        if not self._path.is_file():
            raise AdapterError(
                f"jsonl log is not configured or missing: {self._path}",
                code="scope_unavailable",
            )
        self._key = hmac_key

    def capabilities(self) -> Capabilities:
        return Capabilities(
            adapter_id=self.adapter_id,
            can_scan=True,
            can_delete=True,
            can_redact=True,
            can_invalidate=False,
            can_verify=True,
            notes=["Configured JSONL file only; delete rewrites the file atomically."],
        )

    def _lines(self) -> list[str]:
        try:
            return self._path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise AdapterError(f"jsonl log unreadable: {exc}", code="store_unreadable") from exc

    def _events(self) -> list[dict]:
        events: list[dict] = []
        for index, line in enumerate(self._lines()):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    payload = {"_malformed": True, "content": line}
            except json.JSONDecodeError:
                payload = {"_malformed": True, "content": line}
            payload["_line_index"] = index
            payload["_event_id"] = self._event_id(payload, index, line)
            events.append(payload)
        return events

    def _event_id(self, payload: dict, index: int, line: str) -> str:
        explicit = payload.get("event_id") or payload.get("id")
        if explicit:
            return str(explicit)
        # Stable across line shifts and independent of the line number.
        return "sha-" + fingerprint(line, self._key)[:24]

    # Values that are Redacto's own bookkeeping, never user content.
    _INTERNAL_KEYS = {"_line_index", "_event_id", "_malformed"}
    # Event metadata. Scanned for secrets in `_content`, but excluded from the
    # primary text used for match-ratio sizing.
    _METADATA_KEYS = {
        "event_id",
        "id",
        "kind",
        "ts",
        "timestamp",
        "created_at",
        "sensitivity",
    }
    MAX_WALK_DEPTH = 64

    @classmethod
    def _content(cls, payload: dict) -> str:
        """Every key and string value in the event, at any depth.

        Dict *keys* are included, so `args: {"id": "<secret>"}` is visible. Identity
        fields such as `event_id`, `kind`, `ts` and `sensitivity` are included too: a
        secret stored in one of them is still a secret on disk. Only Redacto's own
        private markers are skipped.
        """
        parts: list[str] = []
        seen: set[int] = set()

        def walk(value, depth: int = 0) -> None:
            if depth > cls.MAX_WALK_DEPTH:
                return
            if isinstance(value, str):
                if value:
                    parts.append(value)
                return
            if isinstance(value, (dict, list)):
                marker = id(value)
                if marker in seen:
                    return
                seen.add(marker)
            if isinstance(value, dict):
                for key, item in value.items():
                    key_text = str(key)
                    if key_text in cls._INTERNAL_KEYS:
                        continue
                    if key_text:
                        parts.append(key_text)
                    walk(item, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    walk(item, depth + 1)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                parts.append(str(value))

        walk(payload)
        return "\n".join(parts)

    @classmethod
    def _primary_text(cls, payload: dict) -> str:
        """The event's payload text: string values only, no keys, no bookkeeping.

        Used for match-ratio sizing. Keys such as `arguments` or `headers` are
        excluded so they do not inflate the denominator. When the event has a
        canonical content field, that field is the primary text.
        """
        canonical = [
            str(payload.get(key))
            for key in ("content", "text", "message", "output")
            if isinstance(payload.get(key), str) and payload.get(key)
        ]
        if canonical:
            return "\n".join(canonical)
        parts: list[str] = []
        seen: set[int] = set()

        def walk(value, depth: int = 0) -> None:
            if depth > cls.MAX_WALK_DEPTH:
                return
            if isinstance(value, str):
                if value:
                    parts.append(value)
                return
            if isinstance(value, (dict, list)):
                marker = id(value)
                if marker in seen:
                    return
                seen.add(marker)
            if isinstance(value, dict):
                for key, item in value.items():
                    if str(key) in cls._INTERNAL_KEYS:
                        continue
                    # Event metadata is only metadata at the top level; a nested
                    # `args.id` is a tool-call argument, i.e. payload.
                    if depth == 0 and str(key) in cls._METADATA_KEYS:
                        continue
                    walk(item, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    walk(item, depth + 1)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                parts.append(str(value))

        walk(payload)
        return "\n".join(parts)

    def _to_record(self, payload: dict) -> Record:
        event_id = str(payload["_event_id"])
        return Record(
            record_id=f"log:{event_id}",
            record_type="log",
            store_id=self.store_id,
            locator={"event_id": event_id, "line": str(payload["_line_index"])},
            content=self._content(payload),
            core_content=self._primary_text(payload),
            sensitivity=[str(payload.get("sensitivity"))] if payload.get("sensitivity") else ["unknown"],
            metadata={"kind": str(payload.get("kind", ""))},
        )

    def list_records(self, *, limit: int | None = None) -> Iterable[Record]:
        for payload in self._events():
            yield self._to_record(payload)
            if limit is not None:
                limit -= 1
                if limit <= 0:
                    return

    def read_record(self, locator: dict[str, str]) -> Record:
        event_id = locator.get("event_id")
        if not event_id:
            raise AdapterError("jsonl locator requires 'event_id'", code="invalid_locator")
        for payload in self._events():
            record = self._to_record(payload)
            if record.locator["event_id"] == event_id:
                return record
        raise AdapterError("record no longer exists", code="not_found")

    def delete_record(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        event_id = locator.get("event_id")
        if not event_id:
            raise AdapterError("jsonl locator requires 'event_id'", code="invalid_locator")
        raw_lines = self._lines()
        matches: list[int] = []
        for index, line in enumerate(raw_lines):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    payload = {"_malformed": True, "content": line}
            except json.JSONDecodeError:
                payload = {"_malformed": True, "content": line}
            if self._event_id(payload, index, line) == event_id:
                matches.append(index)
        if not matches:
            raise AdapterError("record no longer exists", code="not_found")

        # Prefer the recorded line if it still holds the same identity; otherwise
        # delete the first matching line. Malformed and duplicate-id lines are
        # matched by their keyed identity, never by a shifted position.
        preferred_line: int | None = None
        if locator.get("line") is not None:
            try:
                preferred_line = int(locator["line"])
            except (TypeError, ValueError):
                preferred_line = None
        target = preferred_line if preferred_line in matches else matches[0]
        if expected_fingerprint:
            line = raw_lines[target]
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    payload = {"_malformed": True, "content": line}
            except json.JSONDecodeError:
                payload = {"_malformed": True, "content": line}
            if fingerprint(self._content(payload), key or self._key) != expected_fingerprint:
                raise AdapterError(
                    "record content changed since planning", code="content_changed"
                )
        self._rewrite_line(event_id, preferred_line=target, transform=lambda line: None)

    def redact_record(
        self,
        locator: dict[str, str],
        spans: Sequence[dict],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        event_id = locator.get("event_id")
        if not event_id:
            raise AdapterError("jsonl locator requires 'event_id'", code="invalid_locator")
        signing_key = key or self._key
        preferred_line: int | None = None
        if locator.get("line") is not None:
            try:
                preferred_line = int(locator["line"])
            except (TypeError, ValueError):
                preferred_line = None

        def transform(line: str) -> str:
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    payload = {"_malformed": True, "content": line}
            except json.JSONDecodeError:
                payload = {"_malformed": True, "content": line}
            if expected_fingerprint and (
                fingerprint(self._content(payload), signing_key) != expected_fingerprint
            ):
                raise AdapterError("record content changed since planning", code="content_changed")
            redacted, count = redact_spans(line, spans, signing_key)
            if count == 0:
                raise AdapterError("no planned span is present any more", code="not_found")
            if not payload.get("_malformed"):
                try:
                    json.loads(redacted)
                except json.JSONDecodeError as exc:
                    raise AdapterError(
                        "redaction would break the event's JSON", code="unsupported_operation"
                    ) from exc
            return redacted

        self._rewrite_line(event_id, preferred_line=preferred_line, transform=transform)

    def _rewrite_line(
        self,
        event_id: str,
        *,
        preferred_line: int | None,
        transform: Callable[[str], str | None],
    ) -> None:
        """Replace (or with None, remove) one event without dropping lines
        appended concurrently.

        The file is read, edited and re-checked before replacing. If another writer
        appended (or rewrote) in between, the edit is recomputed from the new
        content instead of overwriting it with a stale snapshot.
        """
        for _attempt in range(5):
            original = self._path.read_text(encoding="utf-8")
            raw_lines = original.splitlines()
            matches: list[int] = []
            for index, line in enumerate(raw_lines):
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                    if not isinstance(payload, dict):
                        payload = {"_malformed": True, "content": line}
                except json.JSONDecodeError:
                    payload = {"_malformed": True, "content": line}
                if self._event_id(payload, index, line) == event_id:
                    matches.append(index)
            if not matches:
                raise AdapterError("record no longer exists", code="not_found")
            target = preferred_line if preferred_line in matches else matches[0]
            replacement = transform(raw_lines[target])
            remaining = [
                line if index != target else replacement
                for index, line in enumerate(raw_lines)
                if index != target or replacement is not None
            ]
            new_content = "\n".join(remaining) + ("\n" if remaining else "")

            current = self._path.read_text(encoding="utf-8")
            if current != original:
                continue  # someone else changed the file; recompute from fresh state
            try:
                self._atomic_write(new_content, expected_original=original)
            except _LogChanged:
                continue
            return
        raise AdapterError(
            "jsonl log kept changing during delete; no line was removed",
            code="delete_conflict",
            retryable=True,
        )

    def _atomic_write(self, content: str, *, expected_original: str | None = None) -> None:
        """Replace the log with `content`.

        With `expected_original`, lines another writer appended after that snapshot
        are carried over into the new file right before the replace, so a concurrent
        append is not lost. Any other change raises `_LogChanged` so the caller can
        recompute the edit.
        """
        tmp: str | None = None
        try:
            mode = stat.S_IMODE(self._path.stat().st_mode)
            fd, tmp = tempfile.mkstemp(
                dir=str(self._path.parent), prefix=rewrite_temp_prefix(self._path), suffix=".tmp"
            )
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                if expected_original is not None:
                    current = self._path.read_text(encoding="utf-8")
                    if current != expected_original:
                        if not current.startswith(expected_original):
                            raise _LogChanged()
                        appended = current[len(expected_original) :]
                        if content and not content.endswith("\n") and not appended.startswith("\n"):
                            handle.write("\n")
                        handle.write(appended)
            os.chmod(tmp, mode)
            os.replace(tmp, self._path)
            tmp = None
        except OSError as exc:
            raise AdapterError(f"jsonl delete failed: {exc}", code="delete_failed") from exc
        finally:
            # A failed replace must not leave a temp copy of the log (secrets included).
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def write_record(self, record: Record) -> None:
        event_id = record.locator.get("event_id")
        if not event_id:
            raise AdapterError("jsonl locator requires 'event_id'", code="invalid_locator")
        payload = {
            "event_id": event_id,
            "kind": record.metadata.get("kind", "ingested"),
            "content": record.content,
            "sensitivity": ",".join(record.sensitivity) if record.sensitivity else "unknown",
            "ts": record.metadata.get("created_at") or "",
        }
        try:
            existing = self._path.read_text(encoding="utf-8")
            prefix = "" if not existing or existing.endswith("\n") else "\n"
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(prefix + json.dumps(payload, ensure_ascii=False) + "\n")
        except OSError as exc:
            raise AdapterError(f"jsonl write failed: {exc}", code="write_failed") from exc

    def leftover_temp_files(self) -> list[Path]:
        return leftover_rewrite_temps(self._path)

    def verify_absent(self, fingerprint_value: str) -> tuple[bool, list[str]]:
        residuals = 0
        for record in self.list_records():
            if fingerprint(record.content, self._key) == fingerprint_value:
                residuals += 1
        return residuals == 0, ["Verified by rescanning the configured JSONL log."]