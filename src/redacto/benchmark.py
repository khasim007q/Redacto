"""End-to-end labelled discovery, collateral and residual evaluation."""

from __future__ import annotations

import hashlib
import json
import secrets
import re
import tempfile
import time
from collections import defaultdict
from dataclasses import replace
from pathlib import Path

from redacto.engine import Engine
from redacto.evaluation import _prf
from redacto.local import local_settings
from redacto.discovery.normalization import normalize_loose


def run_benchmark(corpus_path: Path, *, split: str = "all", embedding_provider: str = "local_hashing",
                  embedding_model: str | None = None, embedding_revision: str | None = None,
                  candidate_threshold: float | None = None, quarantine_threshold: float | None = None,
                  local_files_only: bool = False) -> dict:
    raw = Path(corpus_path).read_bytes()
    corpus = json.loads(raw)
    if corpus.get("schema_version") != 1 or split not in {"all", "dev", "holdout"}:
        raise ValueError("unsupported corpus version or split")
    totals = defaultdict(int)
    categories = defaultdict(lambda: defaultdict(int))
    results = []
    start = time.perf_counter()
    neural = embedding_provider in {"sentence_transformers", "sentence-transformers"}
    with tempfile.TemporaryDirectory(prefix="redacto-benchmark-") as temp:
        for scenario in corpus["scenarios"]:
            if split != "all" and scenario["split"] != split:
                continue
            if not isinstance(scenario.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", scenario["id"]):
                raise ValueError("scenario ids must be safe directory names")
            for record in scenario["records"]:
                if not isinstance(record.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", record["id"]):
                    raise ValueError("record ids must be safe filenames")
            root = Path(temp) / scenario["id"]
            settings = replace(local_settings(root, hmac_key=secrets.token_hex(32)), safety_mode="review",
                               embedding_provider=embedding_provider, embedding_model=embedding_model,
                               embedding_revision=embedding_revision, embedding_local_files_only=local_files_only,
                               embedding_candidate_threshold=candidate_threshold if candidate_threshold is not None else (0.55 if neural else 0.25),
                               embedding_quarantine_threshold=quarantine_threshold if quarantine_threshold is not None else (0.60 if neural else 0.30))
            settings.workspace_root.mkdir(parents=True)
            (settings.workspace_root / "source.md").write_text(scenario["source"], encoding="utf-8")
            for record in scenario["records"]:
                (settings.workspace_root / f"{record['id']}.md").write_text(record["text"], encoding="utf-8")
            engine = Engine(settings)
            kind = scenario["target_kind"]
            args = dict(target_id="fs:source.md", target_kind=kind, stores=["filesystem"], use_model=False)
            if kind == "secret":
                args.update(target_text=scenario["source"], mode="fact_revocation")
            # Admit before recording trusted, intentionally incomplete lineage.
            engine.scan(**{k: v for k, v in args.items() if k != "mode"})
            for record in scenario["records"]:
                if record["confirmed"]:
                    engine.record_lineage(source_ids=["fs:source.md"], output_id=f"fs:{record['id']}.md",
                                          relation="DERIVED_FROM", evidence_type="instrumented", evidence_ref="benchmark-writer")
            plan = engine.plan(**args)
            items = {i["record_id"]: i for i in plan["items"]}
            approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="synthetic-benchmark-operator")
            applied = engine.apply(plan_id=plan["plan_id"], plan_version=plan["plan_version"],
                                   approval_ref=approval["approval_ref"], confirmation_token=approval["confirmation_token"], dry_run=False)
            verified = engine.verify(request_id=plan["request_id"])
            guard = engine.guard()
            semantic_ids = {f["record_id"] for f in verified["receipt"]["semantic_verification"]["findings"]}
            for record in scenario["records"]:
                rid = f"fs:{record['id']}.md"
                item = items.get(rid, {})
                found = item.get("evidence_class") in {"DIRECT_MATCH", "CONFIRMED_DESCENDANT", "SUSPECTED_DERIVATIVE", "UNKNOWN"}
                actual = record["discloses"]
                replay = guard.evaluate(record_id=f"replayed:{record['id']}", content=record["text"])
                if actual:
                    totals["replays_blocked"] += int(replay.decision == "blocked")
                    totals["replays_quarantined"] += int(replay.decision == "quarantined")
                    totals["replays_allowed"] += int(replay.decision == "allowed")
                else:
                    totals["safe_replays_blocked"] += int(replay.decision == "blocked")
                    totals["safe_replays_quarantined"] += int(replay.decision == "quarantined")
                bucket = "tp" if actual and found else "fp" if found else "fn" if actual else "tn"
                totals[bucket] += 1
                categories[record["category"]][bucket] += 1
                prefix = "confirmed" if record["confirmed"] else "untracked"
                if actual:
                    totals[f"{prefix}_expected"] += 1
                    totals[f"{prefix}_found"] += int(found)
                remaining = settings.workspace_root / f"{record['id']}.md"
                # Redacted survivors are safe only if the benchmark value is absent.
                residual = actual and remaining.exists()
                if residual and kind == "secret":
                    # An independent labelled-value oracle checks every survivor,
                    # not merely whether any redaction marker was written.
                    compact = lambda text: "".join(normalize_loose(text).split())
                    residual = compact(scenario["source"]) in compact(remaining.read_text(encoding="utf-8"))
                destroyed = not actual and (not remaining.exists() or remaining.read_text(encoding="utf-8") != record["text"])
                totals["residual_disclosures"] += int(residual)
                totals["false_deletions"] += int(destroyed)
                totals["positive_records"] += int(actual)
                totals["negative_records"] += int(not actual)
                if kind == "source":
                    totals["semantic_survivors"] += int(residual)
                    totals["semantic_survivors_flagged"] += int(residual and rid in semantic_ids)
                results.append(dict(scenario=scenario["id"], record=record["id"], split=scenario["split"],
                                    category=record["category"], discloses=actual, confirmed=record["confirmed"],
                                    discovered=found, classification=item.get("evidence_class", "not_found"),
                                    action=item.get("proposed_action", "none"), residual=residual,
                                    semantic_flag=rid in semantic_ids, collateral_damage=destroyed))
            totals["failed_actions"] += applied["counts"]["failed"]
    ratio = lambda n, d: round(n / d, 4) if d else 1.0
    return dict(
        benchmark=corpus["name"], corpus_sha256=hashlib.sha256(raw).hexdigest(), split=split,
        embeddings={"provider": embedding_provider, "model_id": engine.embedder().model_id,
                    "candidate_threshold": settings.embedding_candidate_threshold,
                    "quarantine_threshold": settings.embedding_quarantine_threshold},
        records=len(results), discovery=_prf(totals["tp"], totals["fp"], totals["fn"]),
        confirmed_descendant_recall=ratio(totals["confirmed_found"], totals["confirmed_expected"]),
        untracked_disclosure_recall=ratio(totals["untracked_found"], totals["untracked_expected"]),
        false_deletions=totals["false_deletions"], false_deletion_rate=ratio(totals["false_deletions"], totals["negative_records"]),
        residual_disclosures=totals["residual_disclosures"],
        residual_disclosure_rate=ratio(totals["residual_disclosures"], totals["positive_records"]),
        semantic_residual_recall=ratio(totals["semantic_survivors_flagged"], totals["semantic_survivors"]),
        failed_actions=totals["failed_actions"], elapsed_seconds=round(time.perf_counter() - start, 3),
        replay_guard={"disclosing_blocked": totals["replays_blocked"], "disclosing_quarantined": totals["replays_quarantined"],
                      "disclosing_allowed": totals["replays_allowed"], "safe_blocked": totals["safe_replays_blocked"],
                      "safe_quarantined": totals["safe_replays_quarantined"]},
        by_category={key: _prf(v["tp"], v["fp"], v["fn"]) for key, v in sorted(categories.items())},
        results=results,
        limitations=["Synthetic, template-based corpus; labels are not independently annotated.",
                     "No thresholds are tuned during evaluation; dev/holdout facts and entities are disjoint.",
                     "Only approved actions execute; unresolved disclosures are intentionally retained for review.",
                     "Local neural embeddings were exercised; no external inference service was used."
                     if neural else "No external model or neural embedding is exercised; this is not production recall evidence.",
                     "This benchmark is not evidence of production or universal semantic recall."],
    )
