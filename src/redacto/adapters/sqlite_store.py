"""SQLite adapter for agent memories and cached responses.

Only explicitly approved tables are touched. Table names never come from tool
input, so there is no arbitrary SQL surface.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

from redacto.adapters.base import AdapterError, Capabilities, Record, StoreAdapter
from redacto.discovery.normalization import fingerprint

# table -> (record_type, record_id prefix)
APPROVED_TABLES: dict[str, tuple[str, str]] = {
    "memories": ("memory", "mem"),
    "response_cache": ("cache_entry", "cache"),
}
_REQUIRED_COLUMNS = {"id", "content", "created_at", "sensitivity"}


class SqliteMemoryAdapter(StoreAdapter):
    adapter_id = "sqlite_memory"
    store_id = "sqlite_memory"

    def __init__(self, path: Path, hmac_key: str = "dev-only-synthetic-fixture-key"):
        self._path = path.expanduser().resolve()
        if not self._path.is_file():
            raise AdapterError(
                f"sqlite store is not configured or missing: {self._path}",
                code="scope_unavailable",
            )
        self._key = hmac_key
        try:
            with self._connect() as conn:
                present = self._present_tables(conn)
        except sqlite3.Error as exc:
            raise AdapterError(f"sqlite store unreadable: {exc}", code="store_unreadable") from exc
        if "memories" not in present:
            raise AdapterError(
                "sqlite store must expose the approved 'memories' table", code="invalid_schema"
            )
        self._tables = present
        try:
            with self._connect() as conn:
                self._columns = {
                    table: [
                        row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
                    ]
                    for table in present
                }
        except sqlite3.Error as exc:
            raise AdapterError(f"sqlite store unreadable: {exc}", code="store_unreadable") from exc

    _IDENTITY_PREFIXES = ("mem", "cache")

    def _row_to_record(self, table: str, row: tuple, columns: list[str]) -> Record:
        values = dict(zip(columns, row))
        record_id = values.get("id")
        # Every column is content: a secret in `tags`, `sensitivity` or `created_at`
        # is still on disk. Column names are included so a secret used as a column
        # name is not invisible either.
        parts: list[str] = []
        for column in columns:
            parts.append(str(column))
            value = values.get(column)
            if value is not None:
                parts.append(str(value))
        content = "\n".join(parts)
        sensitivity_raw = str(values.get("sensitivity") or "")
        sensitivity_list = [s for s in sensitivity_raw.split(",") if s]
        return Record(
            record_id=f"{self._prefix(table)}:{record_id}",
            record_type=self._tables[table],
            store_id=self.store_id,
            locator={"table": table, "id": str(record_id)},
            content=content,
            core_content=str(values.get("content") or ""),
            sensitivity=sensitivity_list or ["unknown"],
            metadata={"created_at": str(values.get("created_at") or "")},
        )

    @contextmanager
    def _connect(self):
        """Short-lived connection so Windows file locks are released promptly."""
        conn = sqlite3.connect(self._path, timeout=5)
        # Overwrite deleted cell content instead of leaving it in free pages.
        conn.execute("PRAGMA secure_delete=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _checkpoint(self) -> None:
        conn = None
        try:
            conn = sqlite3.connect(self._path, timeout=5)
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        finally:
            if conn is not None:
                conn.close()

    @staticmethod
    def _present_tables(conn: sqlite3.Connection) -> dict[str, str]:
        """Return approved tables that exist and validate their columns."""
        found: dict[str, str] = {}
        for table, (record_type, _prefix) in APPROVED_TABLES.items():
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if not columns:
                continue
            if not _REQUIRED_COLUMNS.issubset(columns):
                raise AdapterError(
                    f"approved table '{table}' must expose {', '.join(sorted(_REQUIRED_COLUMNS))}",
                    code="invalid_schema",
                )
            found[table] = record_type
        return found

    def unscanned_tables(self) -> list[dict[str, object]]:
        """Tables in this store that are not approved for scan or delete."""
        import sqlite3 as _sqlite3

        conn = None
        try:
            conn = _sqlite3.connect(self._path, timeout=5)
            names = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            ]
            result: list[dict[str, object]] = []
            for name in sorted(set(names) - set(APPROVED_TABLES)):
                columns = [
                    row[1] for row in conn.execute(f"PRAGMA table_info({name})").fetchall()
                ]
                result.append({"table": name, "columns": columns})
            return result
        except _sqlite3.Error:
            return []
        finally:
            if conn is not None:
                conn.close()

    OUT_OF_SCOPE_PREFIX = "sqlx"

    def out_of_scope_records(self, *, limit: int | None = None) -> list[Record]:
        """Rows of unapproved tables, read-only, so a copy there is not silent."""
        remaining = limit
        records: list[Record] = []
        try:
            with self._connect() as conn:
                names = [
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
                    ).fetchall()
                ]
                for name in names:
                    if name in APPROVED_TABLES:
                        continue
                    quoted = '"' + name.replace('"', '""') + '"'
                    columns = [row[1] for row in conn.execute(f"PRAGMA table_info({quoted})")]
                    sql = f"SELECT rowid, * FROM {quoted}"
                    if remaining is not None:
                        sql += f" LIMIT {int(remaining)}"
                    try:
                        rows = conn.execute(sql).fetchall()
                    except sqlite3.Error:
                        continue  # WITHOUT ROWID or unreadable: listed by status only
                    for row in rows:
                        parts: list[str] = []
                        for column, value in zip(columns, row[1:]):
                            parts.append(str(column))
                            if value is not None:
                                parts.append(str(value))
                        records.append(
                            Record(
                                record_id=f"{self.OUT_OF_SCOPE_PREFIX}:{name}:{row[0]}",
                                record_type="unapproved_row",
                                store_id=self.store_id,
                                locator={"table": name, "rowid": str(row[0])},
                                content="\n".join(parts),
                            )
                        )
                    if remaining is not None:
                        remaining -= len(rows)
                        if remaining <= 0:
                            break
        except sqlite3.Error:
            return records
        return records

    def capabilities(self) -> Capabilities:
        return Capabilities(
            adapter_id=self.adapter_id,
            can_scan=True,
            can_delete=True,
            can_redact=False,
            can_invalidate=True,
            can_verify=True,
            notes=[
                "Only approved tables " + ", ".join(sorted(self._tables)) + " are accessed.",
                "INVALIDATE_CACHE is implemented as removal of the cached row.",
            ],
        )

    @staticmethod
    def _prefix(table: str) -> str:
        return APPROVED_TABLES[table][1]

    def list_records(self, *, limit: int | None = None) -> Iterable[Record]:
        remaining = limit
        for table in sorted(self._tables):
            sql = f"SELECT * FROM {table} ORDER BY id"
            if remaining is not None:
                sql += f" LIMIT {int(remaining)}"
            try:
                with self._connect() as conn:
                    rows = conn.execute(sql).fetchall()
            except sqlite3.Error as exc:
                raise AdapterError(f"sqlite scan failed: {exc}", code="scan_failed") from exc
            columns = self._columns[table]
            for row in rows:
                yield self._row_to_record(table, row, columns)
                if remaining is not None:
                    remaining -= 1
                    if remaining <= 0:
                        return

    def read_record(self, locator: dict[str, str]) -> Record:
        table = locator.get("table")
        if table not in self._tables:
            raise AdapterError("unapproved table", code="out_of_scope")
        record_id = locator.get("id")
        if not record_id:
            raise AdapterError("sqlite locator requires 'id'", code="invalid_locator")
        try:
            with self._connect() as conn:
                row = conn.execute(
                    f"SELECT * FROM {table} WHERE id = ?", (record_id,)
                ).fetchone()
        except sqlite3.Error as exc:
            raise AdapterError(f"sqlite read failed: {exc}", code="read_failed") from exc
        if row is None:
            raise AdapterError("record no longer exists", code="not_found")
        return self._row_to_record(table, row, self._columns[table])

    def delete_record(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        table = locator.get("table")
        if table not in self._tables:
            raise AdapterError("unapproved table", code="out_of_scope")
        record_id = locator.get("id")
        if not record_id:
            raise AdapterError("sqlite locator requires 'id'", code="invalid_locator")
        try:
            with self._connect() as conn:
                # IMMEDIATE takes the write lock, so verify + delete cannot interleave
                # with another writer.
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    f"SELECT * FROM {table} WHERE id = ?", (record_id,)
                ).fetchone()
                if row is None:
                    raise AdapterError("record no longer exists", code="not_found")
                if expected_fingerprint and (
                    fingerprint(
                        self._row_to_record(table, row, self._columns[table]).content,
                        key or self._key,
                    )
                    != expected_fingerprint
                ):
                    raise AdapterError(
                        "record content changed since planning", code="content_changed"
                    )
                cursor = conn.execute(f"DELETE FROM {table} WHERE id = ?", (record_id,))
                if cursor.rowcount != 1:
                    raise AdapterError("record no longer exists", code="not_found")
        except AdapterError:
            raise
        except sqlite3.Error as exc:
            raise AdapterError(f"sqlite delete failed: {exc}", code="delete_failed") from exc
        self._checkpoint()

    def invalidate_derived(
        self,
        locator: dict[str, str],
        *,
        expected_fingerprint: str | None = None,
        key: str | None = None,
    ) -> None:
        if locator.get("table") == "response_cache":
            self.delete_record(
                locator, expected_fingerprint=expected_fingerprint, key=key
            )
            return
        raise AdapterError(
            "INVALIDATE_CACHE applies only to the response_cache table",
            code="unsupported_operation",
        )

    def write_record(self, record: Record) -> None:
        table = record.locator.get("table")
        if table not in self._tables:
            raise AdapterError("unapproved table", code="out_of_scope")
        record_id = record.locator.get("id")
        if not record_id:
            raise AdapterError("sqlite locator requires 'id'", code="invalid_locator")
        try:
            with self._connect() as conn:
                conn.execute(
                    f"INSERT OR REPLACE INTO {table} (id, content, created_at, sensitivity) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        record_id,
                        record.content,
                        record.metadata.get("created_at"),
                        ",".join(record.sensitivity),
                    ),
                )
        except sqlite3.Error as exc:
            raise AdapterError(f"sqlite write failed: {exc}", code="write_failed") from exc

    def verify_absent(self, fingerprint_value: str) -> tuple[bool, list[str]]:
        residuals = 0
        for record in self.list_records():
            if fingerprint(record.content, self._key) == fingerprint_value:
                residuals += 1
        return residuals == 0, [
            "Verified by rescanning only the approved tables " + ", ".join(sorted(self._tables)) + "."
        ]
