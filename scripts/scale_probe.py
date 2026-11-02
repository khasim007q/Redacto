"""Reproducible adapter throughput/memory and end-to-end cap-honesty probe.

This is a local SQLite measurement, not a million-record revocation SLA.
"""

import argparse
import json
import platform
import secrets
import sqlite3
import tempfile
import time
import tracemalloc
from contextlib import closing
from pathlib import Path

from redacto.adapters.sqlite_store import SqliteMemoryAdapter
from redacto.engine import Engine
from redacto.local import local_settings


def run(records):
    with tempfile.TemporaryDirectory(prefix="redacto-scale-") as temp:
        settings = local_settings(Path(temp), hmac_key=secrets.token_hex(32))
        settings.workspace_root.mkdir()
        target = "The confidential acquisition costs 48 million dollars."
        (settings.workspace_root / "source.md").write_text(target)
        with closing(sqlite3.connect(settings.sqlite_store_path)) as conn, conn:
            conn.execute("CREATE TABLE memories (id TEXT PRIMARY KEY, content TEXT, created_at TEXT, sensitivity TEXT)")
            conn.executemany("INSERT INTO memories VALUES (?, ?, '', 'public')",
                             ((f"row-{i:09}", f"Public engineering note {i}: the build runs nightly and the SDK supports Linux.") for i in range(records)))
        adapter = SqliteMemoryAdapter(settings.sqlite_store_path, settings.hmac_key)
        tracemalloc.start()
        start = time.perf_counter()
        count = sum(1 for _ in adapter.list_records())
        duration = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        # Execute the full workflow with a deliberately bounded scan and ensure
        # a real residual beyond the cap cannot be reported as fully verified.
        with closing(sqlite3.connect(settings.sqlite_store_path)) as conn, conn:
            conn.execute("INSERT INTO memories VALUES ('zz-residual', ?, '', 'secret')", (target,))
        engine = Engine(settings)
        start = time.perf_counter()
        plan = engine.plan(target_id="fs:source.md", stores=["filesystem", "sqlite_memory"], use_model=False)
        approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="scale-probe-operator")
        engine.apply(plan_id=plan["plan_id"], plan_version=plan["plan_version"], approval_ref=approval["approval_ref"],
                     confirmation_token=approval["confirmation_token"], dry_run=False)
        receipt = engine.verify(request_id=plan["request_id"])
        return {"platform": platform.platform(), "python": platform.python_version(), "records": count,
                "adapter_scan_seconds": round(duration, 3), "adapter_records_per_second": round(count / duration),
                "adapter_peak_traced_bytes": peak, "bounded_workflow_seconds": round(time.perf_counter() - start, 3),
                "workflow_scan_cap": settings.max_scan_records, "verification_status": receipt["status"],
                "sqlite_truncated": next(s["truncated"] for s in receipt["stores"] if s["store_id"] == "sqlite_memory"),
                "limitation": "Adapter iteration is streamed; engine scans remain bounded. This does not measure unbounded graph writes or distributed-store performance."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=100000)
    parser.add_argument("--out")
    args = parser.parse_args()
    if args.records < 1001:
        parser.error("use at least 1001 records to exercise truncation")
    result = run(args.records)
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if result["verification_status"] != "PARTIAL" or not result["sqlite_truncated"]:
        raise SystemExit(1)
