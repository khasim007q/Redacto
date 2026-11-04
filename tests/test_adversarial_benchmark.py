import importlib.util
import json
from pathlib import Path
import pytest

from test_support.benchmark import run_benchmark

ROOT = Path(__file__).resolve().parents[1]


def test_corpus_is_reproducible_and_splits_do_not_share_facts():
    spec = importlib.util.spec_from_file_location("build_benchmark", ROOT / "scripts/build_benchmark.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    corpus = json.loads((ROOT / "tests/data/adversarial-v1.json").read_text(encoding="utf-8"))
    assert corpus == module.build_corpus()
    assert sum(len(s["records"]) for s in corpus["scenarios"]) == 400
    dev = {s["source"] for s in corpus["scenarios"] if s["split"] == "dev"}
    holdout = {s["source"] for s in corpus["scenarios"] if s["split"] == "holdout"}
    assert not dev & holdout


def test_benchmark_reports_missed_disclosures_without_hiding_collateral(tmp_path):
    scenario = {"id": "test", "split": "holdout", "target_kind": "source", "source": "Aster will acquire Lumen for 48 million dollars in November.",
                "records": [
                    {"id": "direct", "category": "direct", "text": "Aster will acquire Lumen for 48 million dollars in November.", "discloses": True, "confirmed": False},
                    {"id": "untracked", "category": "translation", "text": "La compra cuesta cuarenta y ocho millones.", "discloses": True, "confirmed": False},
                    {"id": "safe", "category": "unrelated", "text": "The public SDK supports Linux.", "discloses": False, "confirmed": False},
                ]}
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps({"schema_version": 1, "name": "test", "scenarios": [scenario]}))
    report = run_benchmark(corpus)
    assert report["records"] == 3
    assert report["false_deletions"] == 0
    assert report["discovery"]["false_negatives"] >= 1
    assert report["residual_disclosures"] >= 1
    assert report["residual_disclosure_rate"] > 0
    assert len(report["corpus_sha256"]) == 64


def test_untrusted_corpus_ids_cannot_escape_temporary_stores(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"schema_version": 1, "name": "bad", "scenarios": [
        {"id": "../../escape", "split": "dev", "source": "private", "target_kind": "source", "records": []}]}))
    with pytest.raises(ValueError, match="safe directory"):
        run_benchmark(path)
