"""Chroma vector database adapter (a real vector store, local persistent mode).

Only collections named in REDACTO_CHROMA_COLLECTIONS are touched; collection
names never come from tool input. A record is one stored item: its document
plus every metadata key and value. Deleting removes the item, and with it its
embedding, so INVALIDATE_INDEX and DELETE_RECORD both delete. Text is never
edited in place: an embedding computed from the old text would survive the edit.

Chroma has no transactions, so the content check and the delete are two calls.
The adapter re-reads the item right before deleting and confirms afterwards that
it is gone.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Sequence
import weakref

from redacto.adapters.base import AdapterError, Capabilities, Record, StoreAdapter
from redacto.adapters.vector_fixture import VectorFixtureAdapter
from redacto.discovery.normalization import fingerprint
from redacto.discovery.embeddings import DIMENSION, MODEL_ID, HashingEmbeddingProvider
from redacto.locking import locked_store

PAGE_SIZE = 200
EMBEDDING_MODEL_KEY = "redacto:embedding_model"
EMBEDDING_DIMENSION_KEY = "redacto:embedding_dimension"


def validate_hashing_collection(collection: Any) -> None:
    """Only write vectors into a collection explicitly owned by this embedder.

    Equal dimensions do not imply equal embedding spaces. Never infer ownership
    from an existing vector's shape or silently relabel an external collection.
    """
    metadata = collection.metadata or {}
    if metadata.get(EMBEDDING_MODEL_KEY) != MODEL_ID or metadata.get(EMBEDDING_DIMENSION_KEY) != DIMENSION:
        raise AdapterError(
            "Chroma writes require a collection labelled with Redacto's current embedding model and dimension.",
            code="embedding_model_mismatch",
        )


class ChromaAdapter(StoreAdapter):
    adapter_id = "chroma"
    store_id = "chroma"

    def __init__(
        self,
        path: Path,
        collections: Sequence[str],
        hmac_key: str = "dev-only-synthetic-fixture-key",
        *,
        client: Any = None,
    ):
        self._path = Path(path).expanduser().resolve()
        if not collections:
            raise AdapterError(
                "REDACTO_CHROMA_COLLECTIONS must name the collections Redacto may touch",
                code="scope_unavailable",
            )
        self._key = hmac_key
        self._allowed = tuple(dict.fromkeys(collections))
        owns_client = client is None
        if client is None:
            path = path.expanduser().resolve()
            if not path.is_dir():
                raise AdapterError(f"chroma path is missing: {path}", code="scope_unavailable")
            try:
                import chromadb
            except ImportError as exc:
                raise AdapterError(
                    "chromadb is not installed (pip install 'redacto[chroma]')",
                    code="scope_unavailable",
                ) from exc
            try:
                client = chromadb.PersistentClient(path=str(path))
            except Exception as exc:  # chromadb raises its own error types
                raise AdapterError(f"chroma store unreadable: {exc}", code="store_unreadable") from exc
        self._client = client
        # Short-lived registry adapters must not pin the shared Chroma system
        # (and its SQLite/Windows file handles) for the lifetime of the process.
        close = getattr(client, "close", None)
        self._finalizer = weakref.finalize(self, close) if owns_client and callable(close) else None
        try:
            present = {c if isinstance(c, str) else c.name for c in self._client.list_collections()}
        except Exception as exc:
            raise AdapterError(f"chroma store unreadable: {exc}", code="store_unreadable") from exc
        missing = [name for name in self._allowed if name not in present]
        if missing:
            raise AdapterError(
                "configured chroma collections are missing: " + ", ".join(missing),
                code="scope_unavailable",
            )

    def capabilities(self) -> Capabilities:
        return Capabilities(
            adapter_id=self.adapter_id,
            can_scan=True,
            can_delete=True,
            can_redact=False,
            can_invalidate=True,
            can_verify=True,
            notes=[
                "Chroma collections " + ", ".join(self._allowed) + " only.",
                "Deleting an item removes its embedding; documents are never edited in place.",
            ],
        )

    def _collection(self, name: str | None):
        if name not in self._allowed:
            raise AdapterError("collection is outside the configured scope", code="out_of_scope")
        try:
            return self._client.get_collection(name)
        except Exception as exc:
            raise AdapterError(f"chroma collection unreadable: {exc}", code="store_unreadable") from exc

    def _to_record(self, collection: str, item_id: str, document: str | None, metadata: dict | None) -> Record:
        # Chroma does not return metadata keys in a stable order; sort them so the
        # content fingerprint taken at plan time matches the one at apply time.
        metadata = dict(sorted((metadata or {}).items()))
        payload = {"text": document or "", "metadata": metadata}
        return Record(
            record_id=f"chroma:{collection}/{item_id}",
            record_type="index_entry",
            store_id=self.store_id,
            locator={"collection": collection, "id": str(item_id)},
            content=VectorFixtureAdapter._content(payload),
            core_content=document or "",
            sensitivity=[str((metadata or {}).get("sensitivity"))] if (metadata or {}).get("sensitivity") else ["unknown"],
            metadata={"created_at": str((metadata or {}).get("created_at") or "")},
        )

    def list_records(self, *, limit: int | None = None) -> Iterable[Record]:
        emitted = 0
        for name in self._allowed:
            collection = self._collection(name)
            offset = 0
            while True:
                size = PAGE_SIZE if limit is None else min(PAGE_SIZE, limit - emitted)
                if size <= 0:
                    return
                try:
                    page = collection.get(limit=size, offset=offset, include=["documents", "metadatas"])
                except Exception as exc:
                    raise AdapterError(f"chroma scan failed: {exc}", code="scan_failed") from exc
                ids = page.get("ids") or []
                if not ids:
                    break
                documents = page.get("documents") or [None] * len(ids)
                metadatas = page.get("metadatas") or [None] * len(ids)
                for item_id, document, metadata in zip(ids, documents, metadatas):
                    yield self._to_record(name, item_id, document, metadata)
                    emitted += 1
                    if limit is not None and emitted >= limit:
                        return
                offset += len(ids)
                if len(ids) < size:
                    break

    def _get(self, locator: dict[str, str]) -> tuple[Any, Record | None]:
        collection = self._collection(locator.get("collection"))
        item_id = locator.get("id")
        if not item_id:
            raise AdapterError("chroma locator requires 'id'", code="invalid_locator")
        try:
            page = collection.get(ids=[item_id], include=["documents", "metadatas"])
        except Exception as exc:
            raise AdapterError(f"chroma read failed: {exc}", code="read_failed") from exc
        if not page.get("ids"):
            return collection, None
        documents = page.get("documents") or [None]
        metadatas = page.get("metadatas") or [None]
        return collection, self._to_record(locator["collection"], page["ids"][0], documents[0], metadatas[0])

    def read_record(self, locator: dict[str, str]) -> Record:
        _, record = self._get(locator)
        if record is None:
            raise AdapterError("record no longer exists", code="not_found")
        return record

    @locked_store
    def delete_record(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        collection, record = self._get(locator)
        if record is None:
            raise AdapterError("record no longer exists", code="not_found")
        if expected_fingerprint and fingerprint(record.content, key or self._key) != expected_fingerprint:
            raise AdapterError("record content changed since planning", code="content_changed")
        try:
            collection.delete(ids=[locator["id"]])
        except Exception as exc:
            raise AdapterError(f"chroma delete failed: {exc}", code="delete_failed") from exc
        _, after = self._get(locator)
        if after is not None:
            raise AdapterError("chroma reported the item still present after delete", code="delete_failed")

    def invalidate_derived(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        self.delete_record(locator, expected_fingerprint=expected_fingerprint, key=key)

    @locked_store
    def write_record(self, record: Record) -> None:
        """Reference writer using explicit local embeddings (no model download)."""
        collection = self._collection(record.locator.get("collection"))
        validate_hashing_collection(collection)
        item_id = record.locator.get("id")
        if not item_id:
            raise AdapterError("chroma locator requires 'id'", code="invalid_locator")
        try:
            kwargs = {"ids": [item_id], "documents": [record.content],
                      "embeddings": [HashingEmbeddingProvider().embed(record.content)]}
            if record.metadata:
                kwargs["metadatas"] = [dict(record.metadata)]
            collection.upsert(**kwargs)
        except Exception as exc:
            raise AdapterError("chroma write failed", code="write_failed") from exc

    def verify_absent(self, fingerprint_value: str) -> tuple[bool, list[str]]:
        residuals = sum(
            1 for record in self.list_records() if fingerprint(record.content, self._key) == fingerprint_value
        )
        return residuals == 0, ["Verified by rescanning the configured Chroma collections only."]
