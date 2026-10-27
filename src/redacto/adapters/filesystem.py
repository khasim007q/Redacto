"""Filesystem adapter limited to an explicitly configured root.

Only configured file types inside the root are listable or deletable. Symlinks
and traversal attempts fail closed.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Iterable, Sequence

from redacto.adapters.base import (
    AdapterError,
    Capabilities,
    Record,
    StoreAdapter,
    redact_spans,
    rewrite_temp_prefix,
)
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
            can_redact=True,
            can_invalidate=False,
            can_verify=True,
            can_regenerate=True,
            notes=[
                "Markdown/text files inside the configured root only.",
                "Redaction rewrites a UTF-8 file atomically with the value replaced.",
            ],
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

    def delete_record(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        path = self._safe_path(locator)
        if not path.exists():
            raise AdapterError("record no longer exists", code="not_found")
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            raise AdapterError("record is not an in-scope file", code="out_of_scope")
        if expected_fingerprint:
            try:
                with open(path, "rb") as handle:
                    data = handle.read()
                    stats = os.fstat(handle.fileno())
            except OSError as exc:
                raise AdapterError(f"filesystem read failed: {exc}", code="read_failed") from exc
            content = data.decode("utf-8", errors="replace")
            if fingerprint(content, key or self._key) != expected_fingerprint:
                raise AdapterError(
                    "record content changed since planning", code="content_changed"
                )
            try:
                current = path.stat()
            except OSError as exc:
                raise AdapterError(f"filesystem stat failed: {exc}", code="read_failed") from exc
            # Both identity and stamp must match. The inode alone is not enough:
            # an in-place edit keeps the inode and changes the content.
            same_file = (current.st_dev, current.st_ino) == (stats.st_dev, stats.st_ino)
            same_stamp = (current.st_size, current.st_mtime_ns) == (
                stats.st_size,
                stats.st_mtime_ns,
            )
            if not (same_file and same_stamp):
                raise AdapterError(
                    "record was replaced during apply", code="content_changed"
                )
        try:
            path.unlink()
        except OSError as exc:
            raise AdapterError(f"filesystem delete failed: {exc}", code="delete_failed") from exc

    def redact_record(
        self,
        locator: dict[str, str],
        spans: Sequence[dict],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        def transform(content: str) -> str:
            redacted, count = redact_spans(content, spans, key or self._key)
            if count == 0:
                raise AdapterError("no planned span is present any more", code="not_found")
            return redacted

        self._rewrite(locator, transform, expected_fingerprint=expected_fingerprint, key=key)

    def replace_content(
        self,
        locator: dict[str, str],
        content: str,
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        self._rewrite(
            locator, lambda _old: content, expected_fingerprint=expected_fingerprint, key=key
        )

    def _rewrite(self, locator, transform, *, expected_fingerprint, key) -> None:
        """Atomically rewrite one UTF-8 file after checking it is unchanged."""
        path = self._safe_path(locator)
        if not path.exists():
            raise AdapterError("record no longer exists", code="not_found")
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            raise AdapterError("record is not an in-scope file", code="out_of_scope")
        try:
            with open(path, "rb") as handle:
                data = handle.read()
                stats = os.fstat(handle.fileno())
        except OSError as exc:
            raise AdapterError(f"filesystem read failed: {exc}", code="read_failed") from exc
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AdapterError(
                "file is not UTF-8; it cannot be rewritten safely", code="unsupported_operation"
            ) from exc
        if expected_fingerprint and fingerprint(content, key or self._key) != expected_fingerprint:
            raise AdapterError("record content changed since planning", code="content_changed")
        redacted = transform(content)
        tmp: str | None = None
        try:
            current = path.stat()
            if (current.st_size, current.st_mtime_ns) != (stats.st_size, stats.st_mtime_ns):
                raise AdapterError("record was replaced during apply", code="content_changed")
            fd, tmp = tempfile.mkstemp(
                dir=str(path.parent), prefix=rewrite_temp_prefix(path), suffix=".tmp"
            )
            with os.fdopen(fd, "wb") as handle:
                handle.write(redacted.encode("utf-8"))
            os.chmod(tmp, stat.S_IMODE(stats.st_mode))
            os.replace(tmp, path)
            tmp = None
        except OSError as exc:
            raise AdapterError(f"filesystem rewrite failed: {exc}", code="write_failed") from exc
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def leftover_temp_files(self) -> list[Path]:
        try:
            return sorted(p for p in self._root.rglob(".*.redacto-*.tmp") if p.is_file())
        except OSError:
            return []

    def unscanned_files(self, *, limit: int = 20) -> list[str]:
        """In-scope root files this adapter cannot scan, by extension."""
        found: list[str] = []
        for path in sorted(self._root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            if path.suffix.lower() in SCAN_SUFFIXES:
                continue
            found.append(path.relative_to(self._root).as_posix())
            if len(found) >= limit:
                break
        return found

    def write_record(self, record: Record) -> None:
        path = self._safe_path(record.locator)
        if path.suffix.lower() not in SCAN_SUFFIXES:
            raise AdapterError("only configured text file types may be written", code="out_of_scope")
        if not path.parent.is_dir():
            raise AdapterError("target directory is not in scope", code="out_of_scope")
        try:
            path.write_text(record.content, encoding="utf-8")
        except OSError as exc:
            raise AdapterError(f"filesystem write failed: {exc}", code="write_failed") from exc

    def verify_absent(self, fingerprint_value: str) -> tuple[bool, list[str]]:
        residuals = 0
        for record in self.list_records():
            if fingerprint(record.content, self._key) == fingerprint_value:
                residuals += 1
        limitations = ["Verified by rescanning files under the configured root only."]
        return residuals == 0, limitations
