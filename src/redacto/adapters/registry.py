"""Adapter registry.

Adapters are constructed from explicit settings only. Missing or broken
configuration produces an unavailable adapter entry, not a broader scope.
"""

from __future__ import annotations

from dataclasses import dataclass

from redacto.adapters.base import AdapterError, StoreAdapter
from redacto.config import Settings
from redacto.errors import HmacKeyError


@dataclass
class AdapterSlot:
    adapter_id: str
    adapter: StoreAdapter | None
    unavailable_reason: str | None = None


def build_adapters(settings: Settings) -> dict[str, AdapterSlot]:
    """Best-effort construction; each adapter fails closed on its own."""
    from redacto.adapters.filesystem import FilesystemAdapter
    from redacto.adapters.jsonl_logs import JsonlLogAdapter
    from redacto.adapters.sqlite_store import SqliteMemoryAdapter
    from redacto.adapters.vector_fixture import VectorFixtureAdapter

    slots: dict[str, AdapterSlot] = {}

    def _add(adapter_id: str, factory) -> None:
        try:
            slots[adapter_id] = AdapterSlot(adapter_id, factory())
        except (AdapterError, HmacKeyError) as exc:
            slots[adapter_id] = AdapterSlot(adapter_id, None, str(exc))

    _add("filesystem", lambda: FilesystemAdapter(settings.workspace_root, settings.current_hmac_key))
    _add("sqlite_memory", lambda: SqliteMemoryAdapter(settings.sqlite_store_path, settings.current_hmac_key))
    _add("jsonl_logs", lambda: JsonlLogAdapter(settings.jsonl_log_path, settings.current_hmac_key))
    _add("vector_fixture", lambda: VectorFixtureAdapter(settings.vector_fixture_path, settings.current_hmac_key))
    return slots


def reachable_adapters(slots: dict[str, AdapterSlot]) -> dict[str, StoreAdapter]:
    return {k: v.adapter for k, v in slots.items() if v.adapter is not None}
