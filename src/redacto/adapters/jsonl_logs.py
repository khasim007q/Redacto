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
from typing import Iterable

from redacto.adapters.base import AdapterError, Capabilities, Record, StoreAdapter
from redacto.discovery.normalization import fingerprint


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
            can_redact=False,
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

    _IDENTITY_KEYS = {
        "event_id",
        "id",
        "kind",
        "ts",
        "timestamp",
        "created_at",
        "sensitivity",
        "_line_index",
        "_event_id",
        "_malformed",
    }

    @classmethod
    def _content(cls, payload: dict) -> str:
        """Every string value in the event, including nested tool-call arguments.

        Identity/metadata keys are skipped so a record id cannot masquerade as
        content, but arguments, payloads and nested objects are all scanned.
        """
        parts: list[str] = []

        def walk(value, depth: int = 0) -> None:
            if depth > 8:
                return
            if isinstance(value, str):
                if value:
                    parts.append(value)
            elif isinstance(value, dict):
                for key, item in value.items():
                    if key in cls._IDENTITY_KEYS:
                        continue
                    walk(item, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    walk(item, depth + 1)

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
        remaining = [line for index, line in enumerate(raw_lines) if index != target]
        self._atomic_write("\n".join(remaining) + ("\n" if remaining else ""))

    def _atomic_write(self, content: str) -> None:
        try:
            mode = stat.S_IMODE(self._path.stat().st_mode)
            fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            os.chmod(tmp, mode)
            os.replace(tmp, self._path)
        except OSError as exc:
            raise AdapterError(f"jsonl delete failed: {exc}", code="delete_failed") from exc

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

    def verify_absent(self, fingerprint_value: str) -> tuple[bool, list[str]]:
        residuals = 0
        for record in self.list_records():
            if fingerprint(record.content, self._key) == fingerprint_value:
                residuals += 1
        return residuals == 0, ["Verified by rescanning the configured JSONL log."]