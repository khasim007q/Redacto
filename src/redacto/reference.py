"""Persistent, guarded RAG/memory reference application.

SQLite memories and response cache, a real persistent Chroma retrieval index,
filesystem sources and JSONL output events all use Engine.ingest. Application
operations share a local write boundary with revocation. No agent-facing
approval API is exposed. This example uses extractive summaries to make the
before/after evidence reproducible without an external inference service.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import os
import sqlite3
from dataclasses import replace
from contextlib import closing, asynccontextmanager
from pathlib import Path

from redacto.adapters.base import AdapterError, Record
from redacto.adapters.chroma_store import EMBEDDING_DIMENSION_KEY, EMBEDDING_MODEL_KEY, validate_hashing_collection
from redacto.discovery.embeddings import DIMENSION, MODEL_ID, HashingEmbeddingProvider
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.local import local_settings
from redacto.locking import resource_lock

_ID = re.compile(r"[a-zA-Z0-9_-]{1,80}\Z")


class MemoryApplication:
    def __init__(self, root: Path):
        import chromadb

        root = Path(root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        with resource_lock(root / "graph.sqlite3"):
            key_path = root / "hmac.key"
            if not key_path.exists():
                with key_path.open("x", encoding="utf-8") as handle:
                    handle.write(secrets.token_hex(32))
                key_path.chmod(0o600)
            settings = local_settings(root, hmac_key=key_path.read_text(encoding="utf-8"))
            settings.workspace_root.mkdir(exist_ok=True)
            with closing(sqlite3.connect(settings.sqlite_store_path)) as conn, conn:
                for table in ("memories", "response_cache"):
                    conn.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, content TEXT NOT NULL, created_at TEXT, sensitivity TEXT)")
            if not settings.jsonl_log_path.exists():
                settings.jsonl_log_path.write_text("", encoding="utf-8")
            # Empty legacy fixture stays outside the application's data path.
            if not settings.vector_fixture_path.exists():
                settings.vector_fixture_path.write_text('{"chunks": []}\n', encoding="utf-8")
            chroma_path = root / "chroma"
            chroma_path.mkdir(exist_ok=True)
            self._client = chromadb.PersistentClient(path=str(chroma_path))
            try:
                # Metadata is assigned only on creation. Passing it through
                # get_or_create may overwrite an existing collection's identity.
                if "context" in {c if isinstance(c, str) else c.name for c in self._client.list_collections()}:
                    self._index = self._client.get_collection("context")
                else:
                    self._index = self._client.create_collection("context", metadata={
                        EMBEDDING_MODEL_KEY: MODEL_ID, EMBEDDING_DIMENSION_KEY: DIMENSION,
                    })
                validate_hashing_collection(self._index)
            except Exception:
                self._client.close()
                raise
            self.engine = Engine(replace(settings, chroma_path=chroma_path, chroma_collections=("context",),
                                         model_provider="extractive", regenerate_derivatives=True))

    @staticmethod
    def _id(value: str) -> str:
        if not isinstance(value, str) or not _ID.fullmatch(value):
            raise RedactoError("invalid_id", "Use a short alphanumeric id with underscores or hyphens.")
        return value

    def _admit(self, record: Record, *, sources: list[str] = ()) -> str:
        # Admission checks the serialized record as well as its payload: secrets
        # in metadata and identifiers cannot hide outside the guard's input.
        guarded = record.model_copy(update={"content": json.dumps(record.model_dump(), ensure_ascii=False)})
        decision = self.engine.guard().evaluate(record_id=record.record_id, content=guarded.content)
        if decision.decision != "allowed":
            raise RedactoError("admission_refused", "Record requires revocation review.", {"decision": decision.decision})
        result = self.engine.ingest([record], store_id=record.store_id, write_to_store=True)
        if result["counts"]["allowed"] != 1:
            raise RedactoError("admission_refused", "Record was not admitted.", {"counts": result["counts"]})
        if sources:
            self.engine.record_lineage(source_ids=sources, output_id=record.record_id,
                                       relation="DERIVED_FROM", evidence_type="instrumented",
                                       evidence_ref="reference-application-writer")
        return record.record_id

    def document(self, identity: str, text: str) -> dict:
        identity = self._id(identity)
        with self.engine.write_boundary():
            rid = self._admit(Record(record_id=f"fs:{identity}.md", record_type="doc", store_id="filesystem",
                                     locator={"path": f"{identity}.md"}, content=text))
            self._index_record(identity, text, [rid])
            return {"record_id": rid}

    def _index_record(self, identity: str, text: str, sources: list[str]) -> str:
        return self._admit(Record(record_id=f"chroma:context/{identity}", record_type="index_entry", store_id="chroma",
                                  locator={"collection": "context", "id": identity}, content=text), sources=sources)

    def remember(self, identity: str, text: str, *, sources: list[str] = ()) -> dict:
        identity = self._id(identity)
        with self.engine.write_boundary():
            self._check_sources(sources)
            rid = self._admit(Record(record_id=f"mem:{identity}", record_type="memory", store_id="sqlite_memory",
                                     locator={"table": "memories", "id": identity}, content=text), sources=sources)
            self._index_record(f"memory-{identity}", text, [rid])
            return {"record_id": rid}

    def _check_sources(self, sources: list[str]) -> list[str]:
        texts = []
        slots = self.engine.adapters()
        for source_id in sources:
            source = self.engine.repo.get_record(source_id)
            if source is None or source["status"] != "active":
                raise RedactoError("source_unavailable", "A requested source is unavailable or revoked.")
            slot = slots.get(source["store_id"])
            if not slot or slot.adapter is None:
                raise RedactoError("source_unavailable", "A requested source cannot be read.")
            record = slot.adapter.read_record(source["locator"])
            if self.engine.guard().evaluate(record_id=source_id, content=record.content).decision != "allowed":
                raise RedactoError("source_revoked", "A requested source is blocked or requires review.")
            texts.append(record.core_content or record.content)
        return texts

    def summarize(self, identity: str, sources: list[str]) -> dict:
        if not sources:
            raise RedactoError("missing_sources", "A summary requires at least one source.")
        with self.engine.write_boundary():
            text = "\n".join(self._check_sources(sources))
            return self.remember(identity, text, sources=sources)

    def query(self, question: str, *, limit: int = 5) -> dict:
        with self.engine.write_boundary():
            guard = self.engine.guard()
            page = self._index.query(query_embeddings=[HashingEmbeddingProvider().embed(question)],
                                     n_results=max(1, min(limit, 20)), include=["documents", "metadatas"])
            # Guard at retrieval as well as writes: direct index bypasses are
            # filtered while the explicit reconciliation report records them.
            hits = []
            metadatas = (page.get("metadatas") or [[None] * len(page["ids"][0])])[0]
            for identity, text, metadata in zip(page["ids"][0], page["documents"][0], metadatas):
                # Use the same envelope as discovery: a direct writer can hide a
                # revoked value in metadata or the item's identity, too.
                envelope = json.dumps({"id": identity, "text": text, "metadata": metadata}, ensure_ascii=False)
                if text and guard.evaluate(record_id=f"chroma:context/{identity}", content=envelope).decision == "allowed":
                    hits.append((identity, text))
            answer = "\n".join(text for _, text in hits)
            if answer:
                identity = hashlib.sha256(question.encode()).hexdigest()[:24]
                sources = [f"chroma:context/{item}" for item, _ in hits]
                self._admit(Record(record_id=f"cache:{identity}", record_type="cache_entry", store_id="sqlite_memory",
                                   locator={"table": "response_cache", "id": identity}, content=answer), sources=sources)
                event_id = secrets.token_hex(12)
                self._admit(Record(record_id=f"log:{event_id}", record_type="log", store_id="jsonl_logs",
                                   locator={"event_id": event_id}, content=answer), sources=sources)
            return {"answer": answer, "record_ids": [f"chroma:context/{item}" for item, _ in hits]}

    def reconcile(self) -> dict:
        with self.engine.write_boundary():
            return self.engine.reingest_stores()

    def close(self) -> None:
        self._client.close()


def create_app(root: Path, *, token: str | None = None):
    """ASGI app; approval and destructive operations stay in the local CLI."""
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.concurrency import run_in_threadpool
    from starlette.middleware.base import BaseHTTPMiddleware

    token = token or os.environ.get("REDACTO_HTTP_TOKEN")
    if not token:
        raise RedactoError("http_token_required", "Set REDACTO_HTTP_TOKEN before serving the reference application.")
    application = MemoryApplication(root)

    async def mutate(request: Request):
        try:
            body = await request.json()
            if not isinstance(body, dict):
                raise ValueError("object required")
            op = request.path_params["operation"]
            if op in {"documents", "memories"} and not isinstance(body.get("text"), str):
                raise ValueError("text must be a string")
            if op in {"memories", "summaries"}:
                sources = body.get("sources", [])
                if not isinstance(sources, list) or not all(isinstance(source, str) for source in sources):
                    raise ValueError("sources must be a list of ids")
            if op == "documents":
                result = await run_in_threadpool(application.document, body["id"], body["text"])
            elif op == "memories":
                result = await run_in_threadpool(application.remember, body["id"], body["text"], sources=body.get("sources", []))
            elif op == "summaries":
                result = await run_in_threadpool(application.summarize, body["id"], body["sources"])
            else:
                return JSONResponse({"error": "unknown_operation"}, status_code=404)
            return JSONResponse(result)
        except RedactoError as exc:
            return JSONResponse(exc.as_dict(), status_code=409)
        except (ValueError, KeyError, TypeError):
            return JSONResponse({"error": "invalid_request"}, status_code=400)

    async def query(request: Request):
        try:
            return JSONResponse(await run_in_threadpool(application.query, request.query_params.get("q", "")))
        except RedactoError as exc:
            return JSONResponse(exc.as_dict(), status_code=409)

    @asynccontextmanager
    async def lifespan(_app):
        try:
            yield
        finally:
            application.close()

    app = Starlette(routes=[Route("/query", query), Route("/{operation}", mutate, methods=["POST"])], lifespan=lifespan)

    async def authenticate(request, call_next):
        expected = f"Bearer {token}".encode("utf-8")
        supplied = request.headers.get("authorization", "").encode("utf-8")
        if not hmac.compare_digest(supplied, expected):
            return JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
        return await call_next(request)

    app.add_middleware(BaseHTTPMiddleware, dispatch=authenticate)
    return app
