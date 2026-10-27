"""Read-only HTML report: complete, escaped, and free of record content."""

from __future__ import annotations

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.engine import Engine
from redacto.fixtures import ACQUISITION_PLAN, SOURCE_ID
from redacto.report import build_report


def test_report_covers_every_section_without_content(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    applied = approve_and_apply(engine, plan)
    engine.verify(request_id=applied["request_id"])
    html = build_report(engine, request_id=applied["request_id"])
    for heading in ("Stores", "Lineage", "Plan preview", "Execution timeline", "Verification receipt"):
        assert f"<h2>{heading}</h2>" in html
    assert "fs:generated-summary.md" in html  # confirmed descendant in lineage and plan
    assert 'class="edge candidate"' in html and 'class="edge confirmed"' in html
    assert "not a claim of universal erasure" in html
    for line in ACQUISITION_PLAN.splitlines():
        if len(line) > 30:
            assert line not in html


def test_report_escapes_record_ids(tmp_path):
    import json

    settings = seeded_settings(tmp_path)
    with settings.jsonl_log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"event_id": "<img src=x onerror=alert(1)>", "content": "hi"}) + "\n")
    engine = Engine(settings)
    plan = engine.plan(target_id="log:<img src=x onerror=alert(1)>")
    html = build_report(engine, request_id=plan["request_id"])
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_report_cli_writes_the_file(tmp_path, monkeypatch, capsys):
    from redacto import cli

    settings = seeded_settings(tmp_path)
    plan = Engine(settings).plan(target_id=SOURCE_ID)
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    out = tmp_path / "out" / "report.html"
    assert cli.main(["report", "--request-id", plan["request_id"], "--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
