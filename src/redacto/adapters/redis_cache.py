"""Redis cache adapter.

Only keys matching REDACTO_REDIS_KEY_PATTERNS (Redis glob patterns such as
`llm-cache:*`) are in scope; patterns never come from tool input. Strings,
hashes and lists are read; other types are left alone. Each key is one cache
entry, so the plan's action is INVALIDATE_CACHE, which deletes the key.

The content check and the delete run under WATCH/MULTI/EXEC: if the key changes
between the check and the delete, the transaction aborts and nothing is
deleted.
"""

from __future__ import annotations

import json
from fnmatch import fnmatchcase
from typing import Any, Iterable, Sequence

from redacto.adapters.base import AdapterError, Capabilities, Record, StoreAdapter
from redacto.adapters.vector_fixture import VectorFixtureAdapter
from redacto.discovery.normalization import fingerprint

READABLE_TYPES = {"string", "hash", "list"}


class RedisCacheAdapter(StoreAdapter):
    adapter_id = "redis_cache"
    store_id = "redis_cache"

    def __init__(
        self,
        url: str | None,
        patterns: Sequence[str],
        hmac_key: str = "dev-only-synthetic-fixture-key",
        *,
        client: Any = None,
    ):
        if not patterns:
            raise AdapterError(
                "REDACTO_REDIS_KEY_PATTERNS must name the cache keys Redacto may touch",
                code="scope_unavailable",
            )
        if any(pattern.strip() in {"*", ""} for pattern in patterns):
            raise AdapterError(
                "a bare '*' key pattern would put the whole Redis database in scope",
                code="scope_unavailable",
            )
        self._patterns = tuple(dict.fromkeys(patterns))
        self._key = hmac_key
        if client is None:
            try:
                import redis
            except ImportError as exc:
                raise AdapterError(
                    "redis is not installed (pip install 'redacto[redis]')", code="scope_unavailable"
                ) from exc
            client = redis.Redis.from_url(url, socket_timeout=5)
        self._redis = client
        try:
            self._redis.ping()
        except Exception as exc:
            raise AdapterError(f"redis unreachable: {type(exc).__name__}", code="scope_unavailable") from exc

    def capabilities(self) -> Capabilities:
        return Capabilities(
            adapter_id=self.adapter_id,
            can_scan=True,
            can_delete=True,
            can_redact=False,
            can_invalidate=True,
            can_verify=True,
            notes=[
                "Redis keys matching " + ", ".join(self._patterns) + " only.",
                "Invalidation deletes the key under WATCH/MULTI, so a concurrent change aborts it.",
            ],
        )

    @staticmethod
    def _text(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    # Fields that hold the cached answer itself. When present they are the
    # payload; the prompt and bookkeeping fields are scanned but not sized.
    CANONICAL_FIELDS = ("content", "text", "message", "output", "answer", "response", "completion", "result")

    @classmethod
    def _canonical(cls, mapping: dict) -> str:
        canonical = [str(mapping[k]) for k in cls.CANONICAL_FIELDS if isinstance(mapping.get(k), str) and mapping[k]]
        if canonical:
            return "\n".join(canonical)
        return "\n".join(str(v) for v in mapping.values() if isinstance(v, str))

    def _in_scope(self, key: str) -> bool:
        return any(fnmatchcase(key, pattern) for pattern in self._patterns)

    def _read(self, client: Any, key: str) -> tuple[str, str] | None:
        """(record content, payload text) for a key, or None if absent/unreadable."""
        kind = self._text(client.type(key))
        if kind == "none":
            return None
        if kind not in READABLE_TYPES:
            return "", ""
        if kind == "string":
            raw = self._text(client.get(key))
            try:
                parsed = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                parsed = None
            value = parsed if isinstance(parsed, (dict, list)) else raw
            core = self._canonical(parsed) if isinstance(parsed, dict) else raw
            return VectorFixtureAdapter._content({"key": key, "value": value}), core
        if kind == "hash":
            fields = dict(sorted((self._text(k), self._text(v)) for k, v in client.hgetall(key).items()))
            core = self._canonical(fields)
            return VectorFixtureAdapter._content({"key": key, "value": fields}), core
        items = [self._text(v) for v in client.lrange(key, 0, -1)]
        return VectorFixtureAdapter._content({"key": key, "value": items}), "\n".join(items)

    def _to_record(self, key: str, content: str, core: str) -> Record:
        return Record(
            record_id=f"redis:{key}",
            record_type="cache_entry",
            store_id=self.store_id,
            locator={"key": key},
            content=content,
            core_content=core,
            sensitivity=["unknown"],
        )

    def list_records(self, *, limit: int | None = None) -> Iterable[Record]:
        emitted = 0
        seen: set[str] = set()
        try:
            for pattern in self._patterns:
                for raw_key in self._redis.scan_iter(match=pattern, count=200):
                    key = self._text(raw_key)
                    if key in seen:
                        continue
                    seen.add(key)
                    read = self._read(self._redis, key)
                    if read is None or not read[0]:
                        continue
                    yield self._to_record(key, *read)
                    emitted += 1
                    if limit is not None and emitted >= limit:
                        return
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError(f"redis scan failed: {type(exc).__name__}", code="scan_failed") from exc

    def _checked_key(self, locator: dict[str, str]) -> str:
        key = locator.get("key")
        if not key:
            raise AdapterError("redis locator requires 'key'", code="invalid_locator")
        if not self._in_scope(key):
            raise AdapterError("key is outside the configured patterns", code="out_of_scope")
        return key

    def read_record(self, locator: dict[str, str]) -> Record:
        key = self._checked_key(locator)
        read = self._read(self._redis, key)
        if read is None or not read[0]:
            raise AdapterError("record no longer exists", code="not_found")
        return self._to_record(key, *read)

    def delete_record(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        redis_key = self._checked_key(locator)
        try:
            from redis.exceptions import WatchError
        except ImportError:  # pragma: no cover - the client came from redis
            WatchError = RuntimeError  # noqa: N806
        try:
            with self._redis.pipeline() as pipe:
                pipe.watch(redis_key)
                read = self._read(pipe, redis_key)
                if read is None:
                    raise AdapterError("record no longer exists", code="not_found")
                if expected_fingerprint and fingerprint(read[0], key or self._key) != expected_fingerprint:
                    raise AdapterError("record content changed since planning", code="content_changed")
                pipe.multi()
                pipe.delete(redis_key)
                pipe.execute()
        except WatchError as exc:
            raise AdapterError("cache entry changed during delete", code="content_changed") from exc
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError(f"redis delete failed: {type(exc).__name__}", code="delete_failed") from exc

    def invalidate_derived(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        self.delete_record(locator, expected_fingerprint=expected_fingerprint, key=key)

    def verify_absent(self, fingerprint_value: str) -> tuple[bool, list[str]]:
        residuals = sum(
            1 for record in self.list_records() if fingerprint(record.content, self._key) == fingerprint_value
        )
        return residuals == 0, ["Verified by rescanning the configured Redis key patterns only."]
