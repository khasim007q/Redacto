# Model-assisted discovery: live run

Spec §7.2 and §11.2 ask for model output that is advisory, schema-validated and
benchmarked against the deterministic path. This is one live run against a
local model on the seeded fixture.

**Setup (2026-10-27):** Ollama 0.20.0 on Windows 11 with `llama3:latest`
(8B, Q4_0) at `http://127.0.0.1:11434/v1`.
`REDACTO_MODEL_PROVIDER=ollama`, `REDACTO_MODEL_TIMEOUT=180`. The scan targets
`fs:acquisition-plan.md`.

| Measure | Result |
|---|---|
| Candidates sent | 6 (snippets masked: numbers, keys, emails, URLs, spelled-out amounts) |
| Schema-valid answers | 6 of 6; 0 unassessed; no provider error |
| Latency, cold model | 45 s for the scan, one batch |
| Latency, warm model | about 10 s |
| Approved (destructive) plan items changed by the model | 0 |
| `must_never_touch` records approved | 0 |

Where the model differed from the deterministic labels:

| Record | Without model | With llama3 | Effect |
|---|---|---|---|
| `fs:eng-notes.md` | RELATED_NONDISCLOSING (preserve) | SUSPECTED_DERIVATIVE (review) | False positive. It costs a reviewer a click and deletes nothing |
| `log:evt-instruction` | RELATED_NONDISCLOSING (preserve) | not listed | Assessed as unrelated, so it drops out of the plan. It stays untouched either way |

**Reading.** An 8B local model produces valid JSON reliably, but it is not
precise enough to label siblings: it flagged the unrelated engineering note.
The policy keeps that harmless, because model output can only move a candidate
between review and preserve. Use the deterministic path by default, and turn
the model on only when a reviewer is available.

**Re-run it:**

```bash
REDACTO_LIVE_MODEL_URL=http://127.0.0.1:11434/v1 REDACTO_LIVE_MODEL_NAME=llama3 python -m pytest tests/test_live_model.py
```

The test is skipped unless both variables are set. It fails if the model
changes any approved action or approves a record from `must_never_touch`.
