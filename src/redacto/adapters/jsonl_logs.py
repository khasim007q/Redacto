"""JSONL log adapter: one synthetic event per line.

Deletes rewrite the file atomically after verifying the target line still holds
the expected event ID, so a stale locator can never remove the wrong event.
"""

from __future__ import annotations

import json
import os
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

    def _events(self) -> list[dict]:
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise AdapterError(f"jsonl log unreadable: {exc}", code="store_unreadable") from exc
        events: list[dict] = []
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                payload = {"_malformed": True, "content": line}
            payload["_line_index"] = index
            events.append(payload)
        return events

    @staticmethod
    def _content(payload: dict) -> str:
        parts = [str(payload.get(key, "")) for key in ("content", "text", "message", "output")]
        return "\n".join(part for part in parts if part)

    def _to_record(self, payload: dict) -> Record:
        event_id = str(payload.get("event_id") or payload.get("id") or f"line-{payload['_line_index']}")
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

    def delete_record(self, locator: dict[str, str]) -> None:
        event_id = locator.get("event_id")
        if not event_id:
            raise AdapterError("jsonl locator requires 'event_id'", code="invalid_locator")
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise AdapterError(f"jsonl log unreadable: {exc}", code="store_unreadable") from exc
        target: int | None = None
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            candidate_id = str(payload.get("event_id") or payload.get("id") or f"line-{index}")
            if candidate_id == event_id:
                target = index
                break
        if target is None:
            raise AdapterError("record no longer exists", code="not_found")
        remaining = [line for index, line in enumerate(lines) if index != target]
        self._atomic_write("\n".join(remaining) + ("\n" if remaining else ""))

    def _atomic_write(self, content: str) -> None:
        try:
            fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            os.replace(tmp, self._path)
        except OSError as exc:
            raise AdapterError(f"jsonl delete failed: {exc}", code="delete_failed") from exc

    def verify_absent(self, fingerprint_value: str) -> tuple[bool, list[str]]:
        residuals = 0
        for record in self.list_records():
            if fingerprint(record.content, self._key) == fingerprint_value:
                residuals += 1
        return residuals == 0, ["Verified by rescanning the configured JSONL log."]
