"""Vector-index fixture adapter.

The fixture is a local JSON file of chunks with metadata. It models an index
entry without pretending to integrate a real vector database.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Iterable

from redacto.adapters.base import AdapterError, Capabilities, Record, StoreAdapter
from redacto.discovery.normalization import fingerprint


class VectorFixtureAdapter(StoreAdapter):
    adapter_id = "vector_fixture"
    store_id = "vector_fixture"

    def __init__(self, path: Path, hmac_key: str = "dev-only-synthetic-fixture-key"):
        self._path = path.expanduser().resolve()
        if not self._path.is_file():
            raise AdapterError(
                f"vector fixture is not configured or missing: {self._path}",
                code="scope_unavailable",
            )
        self._key = hmac_key
        self._load()  # validate shape early

    def capabilities(self) -> Capabilities:
        return Capabilities(
            adapter_id=self.adapter_id,
            can_scan=True,
            can_delete=True,
            can_redact=False,
            can_invalidate=True,
            can_verify=True,
            notes=["Local fixture only; invalidate removes the chunk entry (no real vector DB)."],
        )

    def _load(self) -> list[dict]:
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AdapterError(f"vector fixture unreadable: {exc}", code="store_unreadable") from exc
        chunks = payload.get("chunks") if isinstance(payload, dict) else None
        if not isinstance(chunks, list):
            raise AdapterError("vector fixture must be {'chunks': [...]}", code="invalid_schema")
        return chunks

    def _save(self, chunks: list[dict]) -> None:
        try:
            fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"chunks": chunks}, handle, indent=2)
                handle.write("\n")
            os.replace(tmp, self._path)
        except OSError as exc:
            raise AdapterError(f"vector fixture write failed: {exc}", code="delete_failed") from exc

    def _to_record(self, chunk: dict) -> Record:
        chunk_id = str(chunk.get("id") or chunk.get("chunk_id"))
        return Record(
            record_id=f"vec:{chunk_id}",
            record_type="index_entry",
            store_id=self.store_id,
            locator={"id": chunk_id},
            content=str(chunk.get("text") or chunk.get("chunk") or ""),
            sensitivity=[str(chunk.get("sensitivity"))] if chunk.get("sensitivity") else ["unknown"],
            metadata={k: str(v) for k, v in (chunk.get("metadata") or {}).items()},
        )

    def list_records(self, *, limit: int | None = None) -> Iterable[Record]:
        for chunk in self._load():
            yield self._to_record(chunk)
            if limit is not None:
                limit -= 1
                if limit <= 0:
                    return

    def read_record(self, locator: dict[str, str]) -> Record:
        chunk_id = locator.get("id")
        if not chunk_id:
            raise AdapterError("vector locator requires 'id'", code="invalid_locator")
        for chunk in self._load():
            if str(chunk.get("id") or chunk.get("chunk_id")) == chunk_id:
                return self._to_record(chunk)
        raise AdapterError("record no longer exists", code="not_found")

    def delete_record(self, locator: dict[str, str]) -> None:
        chunk_id = locator.get("id")
        if not chunk_id:
            raise AdapterError("vector locator requires 'id'", code="invalid_locator")
        chunks = self._load()
        remaining = [c for c in chunks if str(c.get("id") or c.get("chunk_id")) != chunk_id]
        if len(remaining) == len(chunks):
            raise AdapterError("record no longer exists", code="not_found")
        self._save(remaining)

    def invalidate_derived(self, locator: dict[str, str]) -> None:
        self.delete_record(locator)

    def write_record(self, record: Record) -> None:
        chunk_id = record.locator.get("id")
        if not chunk_id:
            raise AdapterError("vector locator requires 'id'", code="invalid_locator")
        chunks = [c for c in self._load() if str(c.get("id") or c.get("chunk_id")) != chunk_id]
        chunks.append(
            {
                "id": chunk_id,
                "text": record.content,
                "metadata": dict(record.metadata),
                "sensitivity": ",".join(record.sensitivity) if record.sensitivity else "unknown",
            }
        )
        self._save(chunks)

    def verify_absent(self, fingerprint_value: str) -> tuple[bool, list[str]]:
        residuals = 0
        for record in self.list_records():
            if fingerprint(record.content, self._key) == fingerprint_value:
                residuals += 1
        return residuals == 0, ["Verified by rescanning the local vector fixture only."]
