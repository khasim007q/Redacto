"""Development-only labelled disclosure evaluation."""
import argparse
import json
from pathlib import Path
from test_support.benchmark import run_benchmark

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out")
    parser.add_argument("--embedding-provider", default="local_hashing")
    parser.add_argument("--local-files-only", action="store_true")
    parser.add_argument("--split", default="all")
    args = parser.parse_args()
    result = run_benchmark(Path(__file__).parent / "data/adversarial-v1.json", split=args.split,
                           embedding_provider=args.embedding_provider, local_files_only=args.local_files_only)
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "results"}, indent=2))
    raise SystemExit(0 if result["false_deletions"] == 0 and result["failed_actions"] == 0 else 1)
