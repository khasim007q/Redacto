"""Adversarial thread/process tests for the shared local write protocol."""

from __future__ import annotations

import json
import multiprocessing
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from conftest import approve_and_apply
from redacto.adapters.base import Record
from redacto.adapters.jsonl_logs import JsonlLogAdapter
from redacto.adapters.vector_fixture import VectorFixtureAdapter
from redacto.fixtures import SOURCE_ID, ACQUISITION_PLAN
from redacto.locking import resource_lock


def _writer(path, kind, worker, start):
    adapter = JsonlLogAdapter(Path(path), "key") if kind == "jsonl" else VectorFixtureAdapter(Path(path), "key")
    assert start.wait(15)
    for i in range(25):
        identity = f"w{worker}-{i}"
        locator = {"event_id": identity} if kind == "jsonl" else {"id": identity}
        adapter.write_record(Record(record_id=identity, record_type="log", store_id=adapter.store_id, locator=locator, content=f"valuable {identity}"))
        if i % 5 == 0:
            adapter.delete_record(locator)


@pytest.mark.parametrize("kind", ["jsonl", "vector"])
def test_multi_process_writes_and_deletes_lose_no_unrelated_records(tmp_path, kind):
    path = tmp_path / ("events.jsonl" if kind == "jsonl" else "chunks.json")
    path.write_text("" if kind == "jsonl" else '{"chunks": []}', encoding="utf-8")
    ctx = multiprocessing.get_context("spawn")
    start = ctx.Event()
    processes = [ctx.Process(target=_writer, args=(str(path), kind, i, start)) for i in range(3)]
    try:
        for process in processes:
            process.start()
        start.set()
        for process in processes:
            process.join(30)
            assert process.exitcode == 0
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(5)
    adapter = JsonlLogAdapter(path, "key") if kind == "jsonl" else VectorFixtureAdapter(path, "key")
    records = list(adapter.list_records())
    expected = {f"w{w}-{i}" for w in range(3) for i in range(25) if i % 5}
    actual = {r.locator["event_id" if kind == "jsonl" else "id"] for r in records}
    assert actual == expected


def _lock_then_die(path, ready):
    import os
    with resource_lock(Path(path)):
        ready.set()
        os._exit(0)


def test_process_crash_releases_os_lock(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    ready = ctx.Event()
    path = tmp_path / "resource"
    process = ctx.Process(target=_lock_then_die, args=(str(path), ready))
    process.start()
    try:
        assert ready.wait(15)
        process.join(10)
        assert process.exitcode == 0
        with resource_lock(path, timeout=1):
            pass
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)


def test_guarded_write_waits_for_apply_and_observes_new_tombstone(engine, monkeypatch):
    plan = engine.plan(target_id=SOURCE_ID)
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="concurrency-operator")
    slots = engine.adapters()
    adapter = slots["filesystem"].adapter
    original = adapter.delete_record
    entered = threading.Event()
    release = threading.Event()
    writing = threading.Event()

    def pause(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(adapter, "delete_record", pause)
    monkeypatch.setattr(engine, "adapters", lambda: slots)

    def write():
        writing.set()
        return engine.ingest([Record(record_id="fs:restored.md", record_type="doc", store_id="filesystem",
                                     locator={"path": "restored.md"}, content=ACQUISITION_PLAN)],
                             store_id="filesystem", write_to_store=True)

    with ThreadPoolExecutor(2) as pool:
        applying = pool.submit(engine.apply, plan_id=plan["plan_id"], plan_version=plan["plan_version"],
                               approval_ref=approval["approval_ref"], confirmation_token=approval["confirmation_token"], dry_run=False)
        assert entered.wait(10)
        pending = pool.submit(write)
        try:
            assert writing.wait(10)
            assert not pending.done()
        finally:
            release.set()
        assert applying.result(timeout=20)["counts"]["failed"] == 0
        assert pending.result(timeout=20)["counts"]["blocked"] == 1
    assert not (engine.settings.workspace_root / "restored.md").exists()
