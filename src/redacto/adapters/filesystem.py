"""Filesystem adapter limited to an explicitly configured root.

Only configured file types inside the root are listable or deletable. Symlinks
and traversal attempts fail closed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from redacto.adapters.base import AdapterError, Capabilities, Record, StoreAdapter
from redacto.discovery.normalization import fingerprint

SCAN_SUFFIXES = {".md", ".txt", ".rst"}


class FilesystemAdapter(StoreAdapter):
    adapter_id = "filesystem"
    store_id = "filesystem"

    def __init__(self, root: Path, hmac_key: str = "dev-only-synthetic-fixture-key"):
        self._root = root.expanduser().resolve()
        if not self._root.is_dir():
            raise AdapterError(
                f"filesystem root is not configured or not a directory: {self._root}",
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
            notes=["Markdown/text files inside the configured root only."],
        )

    def _safe_path(self, locator: dict[str, str]) -> Path:
        raw = locator.get("path")
        if not raw:
            raise AdapterError("filesystem locator requires 'path'", code="invalid_locator")
        candidate = Path(raw)
        if candidate.is_absolute():
            raise AdapterError("absolute paths are outside scope", code="out_of_scope")
        resolved = (self._root / candidate).resolve()
        try:
            resolved.relative_to(self._root)
        except ValueError as exc:
            raise AdapterError("path traversal is outside scope", code="out_of_scope") from exc
        if resolved == self._root:
            raise AdapterError("directory is not a deletable record", code="invalid_locator")
        return resolved

    def list_records(self, *, limit: int | None = None) -> Iterable[Record]:
        emitted = 0
        for path in sorted(self._root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
                continue
            if path.is_symlink():
                continue
            rel = path.relative_to(self._root).as_posix()
            yield Record(
                record_id=f"fs:{rel}",
                record_type="doc",
                store_id=self.store_id,
                locator={"path": rel},
                content=path.read_text(encoding="utf-8", errors="replace"),
                sensitivity=["unknown"],
                metadata={"suffix": path.suffix.lower()},
            )
            emitted += 1
            if limit is not None and emitted >= limit:
                return

    def read_record(self, locator: dict[str, str]) -> Record:
        path = self._safe_path(locator)
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            raise AdapterError("record is not an in-scope file", code="not_found")
        rel = path.relative_to(self._root).as_posix()
        return Record(
            record_id=f"fs:{rel}",
            record_type="doc",
            store_id=self.store_id,
            locator={"path": rel},
            content=path.read_text(encoding="utf-8", errors="replace"),
            sensitivity=["unknown"],
            metadata={"suffix": path.suffix.lower()},
        )

    def delete_record(self, locator: dict[str, str]) -> None:
        path = self._safe_path(locator)
        if not path.exists():
            raise AdapterError("record no longer exists", code="not_found")
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            raise AdapterError("record is not an in-scope file", code="out_of_scope")
        try:
            path.unlink()
        except OSError as exc:
            raise AdapterError(f"filesystem delete failed: {exc}", code="delete_failed") from exc

    def verify_absent(self, fingerprint_value: str) -> tuple[bool, list[str]]:
        residuals = 0
        for record in self.list_records():
            if fingerprint(record.content, self._key) == fingerprint_value:
                residuals += 1
        limitations = ["Verified by rescanning files under the configured root only."]
        return residuals == 0, limitations
