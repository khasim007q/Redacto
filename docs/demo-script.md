# Redacto demo script (90–120 seconds)

Everything below runs offline against synthetic fixtures. No model provider is
required; if none is configured the flow still completes and semantic candidates
are marked unassessed.

## One-command version (recommended for recording)

```powershell
.venv\Scripts\python.exe -m redacto demo
```

That single command seeds the fixture, prints the graph, creates a plan, issues an
application approval, rehearses with a dry run, applies, verifies and writes
`var/demo_receipt.json` plus `var/demo_receipt.md`.

## Step-by-step version (better for narration)

```powershell
# 1. Reset to the known fixture state
.venv\Scripts\python.exe -m redacto seed

# 2. Show what Redacto can reach
.venv\Scripts\python.exe -m redacto status

# 3. Recorded lineage: authoritative vs weak exposure vs candidates
.venv\Scripts\python.exe -m redacto trace --source-id "fs:acquisition-plan.md"

# 4. Discovery across the four stores
.venv\Scripts\python.exe -m redacto scan --target-id "fs:acquisition-plan.md"

# 5. Draft plan (non-destructive)
.venv\Scripts\python.exe -m redacto plan --target-id "fs:acquisition-plan.md"

# 6. Human approves the exact plan; the application issues a single-use token
.venv\Scripts\python.exe -m redacto approve --plan-id <PLAN_ID> --ref "operator approval in demo"

# 7. Rehearse, then execute
.venv\Scripts\python.exe -m redacto apply --plan-id <PLAN_ID> --version 1 --ref "operator approval in demo" --token <TOKEN> --dry-run
.venv\Scripts\python.exe -m redacto apply --plan-id <PLAN_ID> --version 1 --ref "operator approval in demo" --token <TOKEN>

# 8. Verify and export the receipt
.venv\Scripts\python.exe -m redacto verify --request-id <REQUEST_ID> --out var\receipt.json --markdown var\receipt.md

# 9. Show the tombstone, then re-ingest a restored copy
.venv\Scripts\python.exe -m redacto tombstones
Copy-Item fixtures\workspace\acquisition-plan.md fixtures\workspace\restored.md
.venv\Scripts\python.exe -m redacto ingest --stores filesystem
.venv\Scripts\python.exe -m redacto quarantine
```

`ingest` reports `restored.md` as `blocked` (`exact_fingerprint`): the copy never
enters the provenance graph. A paraphrase is reported as `quarantined`
(`anchor_overlap`) and appears in the quarantine queue instead of being deleted.

## Storyboard with timings

| Time | On screen | Say |
|---|---|---|
| 0:00–0:12 | `fixtures/workspace/acquisition-plan.md` (synthetic confidential plan) | "This is a synthetic confidential source. Agent memory, logs, a summary, a cache and a vector chunk already contain traces of it." |
| 0:12–0:30 | `redacto trace` output | "The graph is authoritative for recorded lineage — five confirmed descendants. This `READ_FROM` link is only exposure evidence: reading a file does not prove what came out of it." |
| 0:30–0:50 | `redacto scan` output | "Discovery adds what lineage missed: an exact duplicate in the logs, two paraphrased candidates with no lineage, and related-but-non-disclosing notes that share only a company name." |
| 0:50–1:05 | `redacto plan` output | "Five deletes, two index/cache invalidations, two candidates held for review, four records preserved. Nothing has been touched yet." |
| 1:05–1:25 | `redacto approve` then `apply` (and a dry run) | "The agent cannot approve. The application issues a single-use token bound to this plan version. The dry run changes nothing; the real apply reports one row per record." |
| 1:25–1:45 | `redacto verify` receipt | "Seven records removed. Zero residual matches in all four reachable stores. The unrelated engineering note is untouched — and so is the file that contained an instruction to delete everything, because scanned content is data, never instructions." |
| 1:45–2:00 | receipt JSON/Markdown | "Two paraphrased candidates still need human review. Verified within configured scope — not a claim of universal erasure." |

## Showing the honest-gap behaviour (optional, 15 seconds)

```powershell
$env:REDACTO_JSONL_PATH = "fixtures/workspace/missing.jsonl"
.venv\Scripts\python.exe -m redacto scan --target-id "fs:acquisition-plan.md"
Remove-Item Env:REDACTO_JSONL_PATH
```

The JSONL store is reported unreachable, its confirmed descendants become
`UNKNOWN` review items, and verification ends `PARTIAL` instead of claiming success.

## Showing the re-ingestion guard (optional, 20 seconds)

```powershell
.venv\Scripts\python.exe -m redacto tombstones
Copy-Item fixtures\workspace\acquisition-plan.md fixtures\workspace\restored.md
.venv\Scripts\python.exe -m redacto ingest --stores filesystem
.venv\Scripts\python.exe -m redacto quarantine
```

Point at the `blocked` decision and explain that the file on disk was not deleted by
the guard: blocking admission is not the same as a new destructive action.

## What to point at when someone asks "did it really work?"

- `var/demo_receipt.json` — counts, per-store outcomes, limitations.
- `tests/` — 53 tests including the failure, injection, idempotency and redaction cases.
- `docs/threat-model.md` — the exact residual risks that stop Redacto claiming universal erasure.