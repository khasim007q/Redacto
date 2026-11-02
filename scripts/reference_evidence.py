"""Run a real persistent-store journey in an isolated temporary application."""

import argparse
import json
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from redacto.reference import MemoryApplication
from redacto.errors import RedactoError
from redacto.discovery.embeddings import HashingEmbeddingProvider


def run():
    with tempfile.TemporaryDirectory(prefix="redacto-reference-") as temp:
        app = MemoryApplication(Path(temp))
        confidential = "Aster will acquire Lumen for 48 million dollars in November. The confidential closing date is November 14."
        public = "The public SDK supports Linux and Windows. Accessibility testing runs on Fridays."
        app.document("private", confidential)
        app.document("public", public)
        app.summarize("mixed", ["fs:private.md", "fs:public.md"])
        before = app.query("Aster Lumen acquisition")
        plan = app.engine.plan(target_id="fs:private.md", depth=5, use_model=False)
        approval = app.engine.approve_plan(plan_id=plan["plan_id"], approval_ref="synthetic-evidence-operator")
        applied = app.engine.apply(plan_id=plan["plan_id"], plan_version=plan["plan_version"], approval_ref=approval["approval_ref"],
                                   confirmation_token=approval["confirmation_token"], dry_run=False)
        after = app.query("SDK Linux")
        clean_receipt = app.engine.verify(request_id=plan["request_id"])
        replay_refused = False
        try:
            app.remember("replayed", confidential)
        except RedactoError as exc:
            replay_refused = exc.code == "admission_refused"
        with closing(sqlite3.connect(app.engine.settings.sqlite_store_path)) as conn, conn:
            summary = conn.execute("SELECT content FROM memories WHERE id='mixed'").fetchone()[0]
            conn.execute("INSERT INTO memories VALUES ('legacy-bypass', ?, '', 'secret')", (confidential,))
        app._index.upsert(ids=["legacy-bypass"], documents=[confidential], embeddings=[HashingEmbeddingProvider().embed(confidential)])
        bypass_answer = app.query("Aster Lumen acquisition")
        reconciliation = app.reconcile()
        bypass_receipt = app.engine.verify(request_id=plan["request_id"])
        app.close()
        return {"stores": ["filesystem", "sqlite_memory", "jsonl_logs", "chroma"],
                "before_query_disclosed": "48 million" in before["answer"],
                "after_query_disclosed": "48 million" in after["answer"],
                "public_context_retained": "Linux" in after["answer"],
                "mixed_summary_retained_only_allowed_source": summary == public,
                "failed_actions": applied["counts"]["failed"],
                "clean_verification_status": clean_receipt["status"],
                "guarded_replay_refused": replay_refused,
                "bypass_retrieval_filtered": "48 million" not in bypass_answer["answer"],
                "bypasses_detected": reconciliation["counts"]["blocked"],
                "bypass_verification_status": bypass_receipt["status"],
                "limitations": ["Real persistent Chroma/SQLite, synthetic content, deterministic extractive generation.",
                                "Direct writes remain possible with filesystem/database access; detection is explicit, not universal prevention."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out")
    args = parser.parse_args()
    result = run()
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    assert result["before_query_disclosed"] and not result["after_query_disclosed"]
    assert result["public_context_retained"] and result["mixed_summary_retained_only_allowed_source"]
    assert result["guarded_replay_refused"] and result["bypass_retrieval_filtered"]
    assert result["failed_actions"] == 0 and result["bypasses_detected"] >= 2
    assert result["bypass_verification_status"] == "PARTIAL"
