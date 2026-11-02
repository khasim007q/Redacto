"""Small application-facing API using the same profile as the MCP operator.

This is trusted application code, not an agent tool. Applications must route all
participating reads/writes through this client; direct database writes bypass it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Sequence
import uuid

from redacto.adapters.base import AdapterError, Record
from redacto.config import load_settings
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.ingestion import ALLOWED


class WorkspaceClient:
    def __init__(self, profile: str | Path):
        self.engine = Engine(load_settings(profile))
        self.engine.settings.current_hmac_key

    @staticmethod
    def _id(value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 200 or any(ord(c) < 32 for c in value):
            raise RedactoError("invalid_record_id", "Use a nonempty record ID of at most 200 characters without control characters.")
        return value

    def read(self, record_id: str) -> Record:
        """Read current store content, refusing revoked or quarantined payloads."""
        with self.engine.write_boundary():
            entry = self.engine._require_record(record_id)
            if entry.get("status") != "active":
                raise RedactoError("record_restricted", "This record is not active.")
            slots = self.engine.adapters()
            slot = slots.get(entry["store_id"])
            if slot is None or slot.adapter is None:
                raise RedactoError("store_unreachable", "The record's configured store is unavailable.")
            try:
                record = slot.adapter.read_record(entry["locator"])
            except AdapterError as exc:
                raise RedactoError("record_unavailable", "Cannot read the current record.", {"adapter_code": exc.code}) from exc
            if self.engine._record_is_oversized(record):
                raise RedactoError("record_restricted", "The record exceeds the configured guard size limit.")
            decision, _ = self.engine._guard_record(self.engine.guard(), record)
            if decision.decision != ALLOWED:
                raise RedactoError("record_restricted", "The current record failed the ingestion guard.",
                                   {"decision": decision.decision, "reason_code": decision.reason_code})
            return record

    def _write(self, record: Record, sources: Sequence[str]) -> dict:
        if isinstance(sources, str) or not all(isinstance(source, str) for source in sources):
            raise RedactoError("invalid_sources", "Pass a sequence of source record IDs.")
        sources = tuple(dict.fromkeys(sources))
        if record.record_id in sources:
            raise RedactoError("invalid_sources", "An output cannot be its own source.")
        with self.engine.write_boundary():
            slot = self.engine.adapters().get(record.store_id)
            if slot is None:
                raise RedactoError("out_of_scope_store", "This store is not enabled by the workspace profile.")
            if slot.adapter is None:
                raise RedactoError("store_unreachable", "The configured write store is unavailable.")
            if record.store_id == "jsonl_logs":
                try:
                    slot.adapter.read_record(record.locator)
                except AdapterError as exc:
                    if exc.code != "not_found":
                        raise RedactoError("record_unavailable", "Cannot check the event identity.") from exc
                else:
                    raise RedactoError("record_exists", "Append an event with a new unique identity.")
            # Validate dependencies before writing; revoked parents cannot generate outputs.
            for source in sources:
                self.read(source)
            written = False
            try:
                result = self.engine.ingest([record], store_id=record.store_id, write_to_store=True)
                if not result["results"][0].get("admitted"):
                    return result
                written = True
                # Store adapters serialize metadata too. Index the actual stored envelope.
                adapter = self.engine.adapters()[record.store_id].adapter
                current = adapter.read_record(record.locator)
                self.engine._upsert_scanned(current, adapter.capabilities().as_dict())
                if sources:
                    self.engine.record_lineage(
                        source_ids=sources, output_id=current.record_id, relation="DERIVED_FROM",
                        evidence_type="instrumented", evidence_ref=f"workspace-write:{uuid.uuid4().hex}",
                    )
                result["lineage_recorded"] = bool(sources)
                return result
            except Exception as exc:
                # The local graph and content stores are not a distributed transaction.
                # Never report a failed graph write as an untouched content store.
                raise RedactoError("integration_write_incomplete",
                                   "The write did not finish. Inspect the store and provenance before retrying.",
                                   {"record_id": record.record_id, "written_to_store": True if written else "unknown",
                                    "cause_code": getattr(exc, "code", "persistence_error")}) from exc

    def write_document(self, relative_path: str, content: str, *, sources: Sequence[str] = ()) -> dict:
        path = PurePosixPath(relative_path.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts or ":" in str(path) or str(path) == ".":
            raise RedactoError("invalid_locator", "Use a relative document path inside the configured workspace.")
        locator = str(path)
        return self._write(Record(record_id=f"fs:{locator}", record_type="doc", store_id="filesystem",
                                  locator={"path": locator}, content=content), sources)

    def _sqlite(self, table: str, prefix: str, kind: str, identity: str, content: str, sources: Sequence[str]) -> dict:
        return self._write(Record(
            record_id=f"{prefix}:{self._id(identity)}", record_type=kind, store_id="sqlite_memory",
            locator={"table": table, "id": identity}, content=content,
            metadata={"created_at": datetime.now(timezone.utc).isoformat()},
        ), sources)

    def remember(self, identity: str, content: str, *, sources: Sequence[str] = ()) -> dict:
        return self._sqlite("memories", "mem", "memory", identity, content, sources)

    def cache(self, identity: str, content: str, *, sources: Sequence[str] = ()) -> dict:
        return self._sqlite("response_cache", "cache", "cache_entry", identity, content, sources)

    def append_event(self, identity: str, content: str, *, sources: Sequence[str] = ()) -> dict:
        return self._write(Record(
            record_id=f"log:{self._id(identity)}", record_type="log", store_id="jsonl_logs",
            locator={"event_id": identity}, content=content,
            metadata={"created_at": datetime.now(timezone.utc).isoformat()},
        ), sources)
