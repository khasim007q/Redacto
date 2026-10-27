"""Vector-index fixture adapter.

The fixture is a local JSON file of chunks with metadata. It models an index
entry without pretending to integrate a real vector database.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Iterable

from redacto.adapters.base import (
    AdapterError,
    Capabilities,
    Record,
    StoreAdapter,
    leftover_rewrite_temps,
    rewrite_temp_prefix,
)
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
        tmp: str | None = None
        try:
            mode = stat.S_IMODE(self._path.stat().st_mode)
            fd, tmp = tempfile.mkstemp(
                dir=str(self._path.parent), prefix=rewrite_temp_prefix(self._path), suffix=".tmp"
            )
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump({"chunks": chunks}, handle, indent=2)
                handle.write("\n")
            os.chmod(tmp, mode)
            os.replace(tmp, self._path)
            tmp = None
        except OSError as exc:
            raise AdapterError(f"vector fixture write failed: {exc}", code="delete_failed") from exc
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    _INTERNAL_KEYS = {"id", "chunk_id"}
    MAX_WALK_DEPTH = 64

    @classmethod
    def _content(cls, chunk: dict) -> str:
        """Every field and nested string in the chunk, including metadata.

        Covers `text`, `chunk`, `content`, `page_content` and any other field a
        producer uses, plus metadata keys and values at any depth.
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
                    # The chunk's own id is identity; a nested "id" is content.
                    if depth == 0 and key_text in cls._INTERNAL_KEYS:
                        continue
                    if key_text:
                        parts.append(key_text)
                    walk(item, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    walk(item, depth + 1)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                parts.append(str(value))

        walk(chunk)
        return "\n".join(parts)

    @classmethod
    def _primary_text(cls, chunk: dict) -> str:
        for key in ("text", "chunk", "content", "page_content"):
            value = chunk.get(key)
            if isinstance(value, str) and value:
                return value
        # No primary text field: fall back to metadata values without their keys.
        parts: list[str] = []

        def walk(value, depth: int = 0) -> None:
            if depth > cls.MAX_WALK_DEPTH:
                return
            if isinstance(value, str):
                if value:
                    parts.append(value)
            elif isinstance(value, dict):
                for key, item in value.items():
                    if str(key) in cls._INTERNAL_KEYS:
                        continue
                    walk(item, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    walk(item, depth + 1)

        walk(chunk)
        return "\n".join(parts)

    def _to_record(self, chunk: dict) -> Record:
        chunk_id = str(chunk.get("id") or chunk.get("chunk_id"))
        return Record(
            record_id=f"vec:{chunk_id}",
            record_type="index_entry",
            store_id=self.store_id,
            locator={"id": chunk_id},
            content=self._content(chunk),
            core_content=self._primary_text(chunk),
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

    def delete_record(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        chunk_id = locator.get("id")
        if not chunk_id:
            raise AdapterError("vector locator requires 'id'", code="invalid_locator")
        chunks = self._load()
        target = next(
            (c for c in chunks if str(c.get("id") or c.get("chunk_id")) == chunk_id), None
        )
        if target is None:
            raise AdapterError("record no longer exists", code="not_found")
        if expected_fingerprint:
            text = self._content(target)
            if fingerprint(text, key or self._key) != expected_fingerprint:
                raise AdapterError(
                    "record content changed since planning", code="content_changed"
                )
        remaining = [c for c in chunks if str(c.get("id") or c.get("chunk_id")) != chunk_id]
        self._save(remaining)

    def invalidate_derived(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        self.delete_record(locator, expected_fingerprint=expected_fingerprint, key=key)

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

    def leftover_temp_files(self) -> list[Path]:
        return leftover_rewrite_temps(self._path)

    def verify_absent(self, fingerprint_value: str) -> tuple[bool, list[str]]:
        residuals = 0
        for record in self.list_records():
            if fingerprint(record.content, self._key) == fingerprint_value:
                residuals += 1
        return residuals == 0, ["Verified by rescanning the local vector fixture only."]
