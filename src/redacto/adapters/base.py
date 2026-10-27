"""Adapter contract shared by every store Redacto can reach.

Adapters only ever see configured scope. Every operation either succeeds with
evidence or raises an AdapterError; a failed mutation is never reported as
successful.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from pydantic import BaseModel, Field


class AdapterError(RuntimeError):
    """Raised when a store cannot be reached or an operation is unsupported."""

    def __init__(self, message: str, *, code: str = "adapter_error", retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable


def rewrite_temp_prefix(path: Path) -> str:
    """Prefix for the temp file a store rewrite writes before `os.replace`."""
    return f".{path.name}.redacto-"


def leftover_rewrite_temps(path: Path) -> list[Path]:
    """Temp copies of `path` left behind by an interrupted rewrite.

    Each holds the whole store as it was before the delete, secrets included.
    `tmp*.tmp` is the name older Redacto versions used.
    """
    parent = path.parent
    try:
        found = set(parent.glob(rewrite_temp_prefix(path) + "*.tmp"))
        found.update(parent.glob("tmp*.tmp"))
    except OSError:
        return []
    return sorted(p for p in found if p.is_file())


class Record(BaseModel):
    """A scannable unit in a store. Content is transient and never persisted."""

    record_id: str
    record_type: str
    store_id: str
    locator: dict[str, str] = Field(default_factory=dict)
    content: str = ""
    # Primary payload text used for match-ratio sizing, or None when the whole
    # `content` is the payload (files). Structured stores put metadata fields and
    # keys into `content` so they are scanned, but they must not inflate the
    # denominator when deciding how much of a record a match covers.
    core_content: str | None = None
    sensitivity: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


@dataclass(frozen=True)
class Capabilities:
    adapter_id: str
    can_scan: bool = True
    can_delete: bool = False
    can_redact: bool = False
    can_invalidate: bool = False
    can_verify: bool = True
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "adapter_id": self.adapter_id,
            "scan": self.can_scan,
            "delete": self.can_delete,
            "redact": self.can_redact,
            "invalidate": self.can_invalidate,
            "verify": self.can_verify,
            "notes": list(self.notes),
        }


class StoreAdapter(ABC):
    """Required operations for a reachable, scoped store."""

    adapter_id: str = "abstract"
    store_id: str = "abstract"

    @abstractmethod
    def capabilities(self) -> Capabilities: ...

    @abstractmethod
    def list_records(self, *, limit: int | None = None) -> Iterable[Record]: ...

    @abstractmethod
    def read_record(self, locator: dict[str, str]) -> Record: ...

    @abstractmethod
    def delete_record(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        """Delete one in-scope record.

        When expected_fingerprint is given the adapter must verify the stored
        content still matches before deleting, and raise AdapterError with code
        content_changed if it does not. Adapters that can do this atomically
        (SQLite) must.
        """

    def write_record(self, record: Record) -> None:
        """Admit a record into this store.

        Ingestion callers must check tombstones before calling this. Adapters that
        cannot write raise; a rejected write is never silently ignored.
        """
        raise AdapterError(
            f"{self.adapter_id}: writing records is not supported", code="unsupported_operation"
        )

    def redact_record(self, locator: dict[str, str], spans: Sequence[str]) -> None:
        raise AdapterError(
            f"{self.adapter_id}: redaction is not supported", code="unsupported_operation"
        )

    def invalidate_derived(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        raise AdapterError(
            f"{self.adapter_id}: invalidation is not supported", code="unsupported_operation"
        )

    @abstractmethod
    def verify_absent(self, fingerprint: str) -> tuple[bool, list[str]]:
        """Return (absent_confirmed, limitations) using only supported methods."""

    def leftover_temp_files(self) -> list[Path]:
        """Uncontrolled copies of this store on disk (for example crashed rewrites)."""
        return []

    def health(self) -> dict[str, object]:
        """Cheap reachability probe used by redacto_status; never leaks content."""
        try:
            count = sum(1 for _ in self.list_records(limit=1))
            return {"reachable": True, "sampled_records": count}
        except AdapterError as exc:
            return {"reachable": False, "error_code": exc.code, "error": str(exc)}
        except OSError as exc:
            return {"reachable": False, "error_code": "io_error", "error": str(exc)}
