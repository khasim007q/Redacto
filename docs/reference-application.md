# Guarded persistent memory application

The reference application uses real persistent Chroma retrieval, SQLite memory
and response-cache tables, Markdown source files and JSONL output events. It
creates its own random persistent HMAC key under the selected application root.
The root must be dedicated to this example; the application never seeds the
repository's fixtures or reads `.env` for store paths.

```powershell
uv sync --frozen --all-extras --python 3.12
$env:REDACTO_HTTP_TOKEN = "<a randomly generated local token>"
uv run --no-sync python -m redacto reference-app --root var/memory-app
```

The server binds `127.0.0.1:8766`. Every route requires
`Authorization: Bearer <token>`. It is a local integration example, not a
production identity provider. The API supports:

| Method/path | JSON body / parameters | Effect |
|---|---|---|
| POST `/documents` | `{"id":"private","text":"..."}` | Guarded source write and Chroma index update |
| POST `/memories` | `{"id":"note","text":"...","sources":["fs:private.md"]}` | Guarded memory/index write and instrumented lineage |
| POST `/summaries` | `{"id":"mixed","sources":["fs:private.md","fs:public.md"]}` | Extractive summary, guarded memory/index write and lineage |
| GET `/query?q=...` | Search question | Guarded retrieval; cache and output log are admitted through the same guard |

Summaries and answers are extractive so the evidence is reproducible without an
external model. This exercises real application persistence, retrieval, lineage,
cache/log writes and revocation. It does not benchmark neural RAG answer quality.
There are no approval or apply endpoints. A local operator uses the ordinary
engine/CLI approval boundary against the application's configuration:

```python
from pathlib import Path
from redacto.reference import MemoryApplication

app = MemoryApplication(Path("var/memory-app"))
plan = app.engine.plan(target_id="fs:private.md", depth=5, use_model=False)
# Inspect plan before issuing approval in the operator process.
approval = app.engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator-ticket-42")
app.engine.apply(plan_id=plan["plan_id"], plan_version=plan["plan_version"],
                 approval_ref=approval["approval_ref"],
                 confirmation_token=approval["confirmation_token"], dry_run=False)
receipt = app.engine.verify(request_id=plan["request_id"])
app.close()
```

The application remains active while another local process revokes data.
`write_boundary()` coordinates its multi-store writes and queries with apply/verify.
Every memory write, index update, response-cache insertion and output event uses
`Engine.ingest`. All instrumented writes record lineage. An unknown legacy writer
can still bypass the guard; retrieval filters known revoked material and
`app.reconcile()` reports blocked/quarantined existing records without deleting them.

## Reproduce the evidence

```powershell
uv run --no-sync python scripts/reference_evidence.py --out benchmarks/reference-local.json
uv run --no-sync python -m pytest -q tests/test_reference_application.py tests/test_concurrent_writers.py
```

The isolated journey ingests confidential and public sources, creates a mixed
summary, queries before revocation, applies an operator-approved plan, then queries
again. The summary is regenerated from the public source with grounding and retention
checks. Mixed query logs are preserved until an operator approves their planned
source-passage redactions and issues approval for the new plan version. The evidence
script performs that explicit review before claiming clean scoped verification.
It attempts replay through the guarded API and deliberate direct SQLite and
Chroma writes. The evidence records successful filtering/detection and a `PARTIAL`
receipt after those bypasses; the original clean receipt is not treated as permanent.

The tests also exercise multi-process JSONL/vector mutations, process death while
holding a lock, a write racing apply, malformed API requests and bearer rejection.
Use a dedicated single-host data directory with restrictive permissions. This example
does not cover distributed transactions, arbitrary direct writers or external replicas.

The evidence script runs the journey in a short-lived worker process. The parent
owns its temporary directory and deletes it after that worker exits, so retained
native Chroma/SQLite handles cannot race Windows cleanup. Application close runs
on failures too. Worker failures, timeouts and directory-cleanup errors still fail
the script; it does not ignore cleanup errors or retry a failed revocation.
