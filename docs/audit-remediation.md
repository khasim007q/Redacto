# Audit remediation and executed evidence

28 October 2026. The original audit reviewed design and documentation without
executing the project. This pass reproduced the baseline (273 passed, 2 opt-in
live-model tests skipped), fixed concrete defects and added executable product
evidence. It does not declare universal or production-ready revocation.

Final local validation from fresh `uv.lock` installations:

| Check | Result |
|---|---|
| Full suite, Windows / Python 3.12.0 | 318 passed, 2 opt-in live-model tests skipped; 96.77 seconds |
| Full suite, Windows / Python 3.14.2 | 318 passed, 2 opt-in live-model tests skipped; 100.11 seconds |
| Additional concurrent-writer runs | Five consecutive runs, 20/20 tests passed |
| Real MCP stdio client | PASS, all eight tools discovered |
| Real MCP HTTP client | PASS, bearer-authenticated session; missing bearer rejected with 401 |
| Fresh runtime-only install | CLI imports successfully without pytest, Chroma or fakeredis |
| Frozen dependency lock and diff whitespace | PASS |

`benchmarks/validation-local.json` records the environment, lock digest and test
counts. JUnit outputs are under `var/validation-312.xml` and
`var/validation-314.xml`. Live external model tests and an external Redis server
were not exercised; Redis transaction behavior was tested with fakeredis. Hosted
Linux/Windows CI is configured but has not been run from this local session.

## Changes against the audit

| Finding | Implemented response | Remaining boundary |
|---|---|---|
| Missing-lineage discovery unmeasured | Versioned 400-record corpus, scenario-level dev/holdout split, per-category precision/recall, confirmed vs untracked recall, collateral, residual and replay metrics | Synthetic templates and authored labels; independent annotation and external workloads still needed |
| Ingestion integration/bypass | Persistent Chroma/SQLite reference app; guarded memory/index/cache/log paths; shared apply/write boundary; retrieval filtering and bypass reconciliation | Direct store access cannot be universally intercepted |
| Exact absence mistaken for semantic absence | Separate advisory survivor assessment; post-plan additions included; unresolved findings produce NEEDS_REVIEW; coverage gaps produce PARTIAL | Translations, approximations and complex transformations remain incomplete |
| Adapter coverage | One complete persistent application rather than additional unvalidated adapters; reference journey tested across four real store types | No PostgreSQL/hosted-vector/object-store integration claim |
| Concurrent mutations | Reentrant OS-backed process locks; JSONL per-retry fingerprint and final snapshot check; vector unique-ID/schema/snapshot validation; file link rejection and final rewrite checks | External writers ignoring locks can still race final filesystem operations |
| Regeneration safety/usefulness | Independent extractive-sentence grounding and 25% per-source distinct-word retention floor; hallucinated/contradictory/empty/useless outputs refused; deterministic extractive implementation; mixed-source retention tests | Conservative gate rejects unsupported paraphrases; not a factual-completeness proof |
| False-positive calibration | Reports category counts, misses, safe replay holds and false deletions; thresholds not retuned by the runner | Template overlap and limited domains constrain generalization |
| Scale | Streamed SQLite adapter iteration; 100,000-row probe plus bounded full workflow with a hidden residual past the cap | No million-record end-to-end or distributed throughput claim |
| Security | Immediate post-apply protection; all active tombstones enforced; single-token/config/glued secret guard; metadata/identity guard; signed receipts; safe transport diagnostics; malformed safety settings fail closed | Production identities/roles, managed secrets and off-host immutable audit remain deployment work |
| Packaging/docs | Compatible MCP major range, constrained dependencies, checked-in uv.lock, frozen-install CI including Chroma; synchronized architecture/scope docs | CI configuration is prepared locally; hosted CI has not been observed in this session |

Concrete defects fixed include the 200-tombstone enforcement cutoff, the interval
between apply and verify without protection, deletion of changed JSONL events on
retry, vector constructor reads racing Windows replacement, unnoticed concurrent
vector rewrites, loss of vector-file top-level metadata, filesystem symlink aliases,
unverified oversized survivors, and single-token secrets entering guarded writes.
Repeated execution also exposed intermittent Windows sharing violations during
replacement and approval tokens starting with a CLI option prefix. Replacements now
retry only recognized transient Windows errors, rechecking the snapshot each time;
issued tokens retain 256 random bits behind a fixed CLI-safe prefix. Regression
tests force both conditions rather than waiting for randomness to reproduce them.

## Adversarial evaluation

Run from the repository root in a fresh locked environment:

```powershell
uv sync --frozen --all-extras --python 3.12
uv run --no-sync python -m pytest -q
uv run --no-sync python -m redacto benchmark --out benchmarks/latest-local.json
uv run --no-sync python -m redacto benchmark --split holdout --out var/holdout.json
uv run --no-sync python scripts/reference_evidence.py --out benchmarks/reference-local.json
uv run --no-sync python scripts/scale_probe.py --records 100000 --out benchmarks/scale-local.json
uv run --no-sync python scripts/mcp_smoke.py
uv run --no-sync python scripts/mcp_http_smoke.py
```

`scripts/build_benchmark.py` reproduces `benchmarks/adversarial-v1.json` byte-for-byte
through deterministic serialization. There are 20 scenarios, 400 labelled records,
240 disclosures and 160 safe records, including 32 instrumented descendants.
Categories cover paraphrases, translations, unit conversions, approximations,
mixed-source records, public siblings, injected instructions and secret variants.
Labels come from authored transformations, not the detector. Every run records the
corpus SHA-256 and per-record outcomes. Neither the runner nor CI tunes thresholds.

The current local result is 230/240 disclosures discovered (95.83% recall), 10 safe
records flagged for review (95.83% precision), 100% confirmed-descendant recall,
95.19% untracked recall and **zero false deletions**. Unit-conversion recall rose
from 9/16 to 16/16 after exact scale canonicalization; total recall rose from 95%
to 95.83%, while precision fell from 96.61% to 95.83%. That tradeoff is retained in
the reports instead of obscured by a single success score.

**116/240 disclosures remain after approved actions.** Most are deliberately
review-only; some are missed. Survivor assessment flags 90.18% of the remaining
source disclosures. Replay evaluation blocks 144 disclosures, quarantines 85 and
allows 11; it blocks no safe records and holds two safe records for review.
This is evidence of incomplete semantic protection, not a successful-erasure rate.
The all-record report includes holdout scenarios; the split is for future controlled
experiments, not a claim of a blinded independent benchmark.

`baseline-local.json` is the first run of this new corpus before quantity
normalization, not a benchmark of the untouched original repository.
`latest-local.json` contains the final current result and replay counts.

## Persistent application and scale

`reference-local.json` records confidential retrieval before revocation, no such
retrieval afterward, retained public context, a mixed summary rebuilt only from its
allowed source, zero failed actions, refused guarded replay and two detected direct
bypasses. The clean receipt is VERIFIED_WITHIN_SCOPE; after bypass injection the
receipt is PARTIAL. Chroma and SQLite are real persistent local databases;
generation is deterministic and the content is synthetic.

`scale-local.json` measures 100,000 SQLite records on Windows/Python 3.12:
1.219 seconds of adapter iteration, about 82,013 records/second and 11,395 peak
Python-traced bytes. Tracemalloc excludes SQLite/native allocations. The bounded
full workflow took 5.687 seconds with a 1,000-record cap and correctly returned
PARTIAL for a residual beyond that cap. This is not unbounded engine throughput.

## Operational limits

Read [compatibility.md](compatibility.md) for atomicity, scope, embedding-version
and key-retirement constraints. Receipts authenticate evidence using HMAC; local
administrators who control both the keyring and database remain trusted. The bundled
development key is only for synthetic fixtures; the reference app creates a random
key per application root. No OAuth identity integration, external audit service,
hosted-store access or universal semantic-erasure proof is claimed.

## Follow-up: boundaries and semantic compatibility, 2 November 2026

The October evidence above is preserved as a historical snapshot. This follow-up
adds an optional real multilingual embedding model and closes additional concrete
enforcement and reporting gaps:

- Credential targets no longer use embedding similarity. Harmless text is not
  quarantined because a random credential happens to share vector features.
  A fact/secret lookup anchor is no longer blocked solely by its record identity.
- Reference retrieval checks index identities, metadata and documents together.
  Direct metadata/identifier bypasses are filtered before caching or logging.
- Chroma writes require the current hashing model/dimension ownership labels;
  equal dimensions do not authorize mixing embedding spaces. Existing external
  collections remain readable/deletable within their configured scope.
- Redis sets, sorted sets and streams are scanned. Unknown module types produce
  a coverage error rather than an empty, apparently clean scan.
- Key retirement protects every retained signed receipt, request and plan-item
  fingerprint as well as active tombstones. Malformed receipt references prevent
  a retirement recommendation; malformed signatures/values return invalid.
- The optional assessor receives a minimized target for comparison and cannot
  dismiss an unresolved deterministic disclosure signal. Stored non-disclosing
  candidate edges no longer short-circuit fresh content checks.
- Model/revision changes are reported as degraded semantic protection. A verify
  operation with incompatible target vectors returns PARTIAL/incomplete instead
  of silently omitting the embedding comparison.

The new local provider uses Sentence Transformers 6.2.0 with pinned multilingual
MiniLM weights, immutable revision
`e8f8c211226b894fcb81acc59f3b34ba3efd5f42`. Model snapshots are resolved explicitly
to prevent a same-named working-directory folder replacing pinned remote weights.
CPU inference, offline cache loading, safetensors transformer weights, disabled
remote model code, bounded overlapping token windows and structured failures are
exercised. No inference API receives record contents. See
[semantic-discovery.md](semantic-discovery.md) for configuration and limitations.

The same 400-record corpus, with fixed initial neural thresholds 0.55/0.60, gives:

| Measurement | Current hashing | Optional neural |
|---|---:|---:|
| Disclosures discovered | 230/240 | 232/240 |
| Precision | 96.23% | 99.57% |
| Recall | 95.83% | 96.67% |
| Safe records flagged | 9 | 1 |
| False deletions | 0 | 0 |
| Detected semantic survivors | 90.18% | 96.43% |
| Disclosing replays allowed | 11 | 4 |
| Safe replays blocked / quarantined | 0 / 2 | 0 / 0 |

These are not uniformly better results in every category: neural discovery misses
six mixed-source records and two unit transformations that the hashing provider
finds. It detects all 16 labelled translations and all 16 approximations, compared
with 12 and 10 respectively for hashing. No threshold was tuned by the runner.
The retained split result is 59/60 disclosures found, zero false positives and no
allowed disclosing replays on 100 records. The corpus and split have already been
inspected; this is not blinded independent validation.

**116/240 disclosures still remain after approved actions**, including review-only
candidates. The optional model improves candidate detection and survivor warning;
it does not turn uncertain matches into automatic deletion or establish erasure.
All four allowed full-corpus replays remain recorded as failures of protection.
Reports: `boundaries-hashing-local.json`, `neural-local.json` and
`neural-holdout-local.json` under `benchmarks/`.

The persistent application journey was rerun (`boundaries-reference-local.json`):
public context and allowed portions of mixed summaries survive, guarded replay is
refused, direct bypass retrieval is filtered, and reconciliation reports two
bypasses. Exact counts, environment versions, the new lock digest and final test
runs are recorded in `benchmarks/boundaries-validation-local.json`.

| Final follow-up check | Executed result |
|---|---|
| Windows / Python 3.12, real neural model enabled | 346 passed, 2 external-assessor tests skipped |
| Windows / Python 3.14, neural extra not installed | 345 passed, 3 opt-in integration tests skipped |
| Real neural inference | Pinned multilingual model; CPU; offline full/split benchmarks |
| Fresh runtime-only wheel | Actual stdio MCP plan from outside the project; no optional dependencies |
| Real HTTP MCP | Authenticated tool discovery/status; missing bearer rejected with 401 |
| Lock consistency and diff whitespace | Passed |

Compatibility was also exercised using a freshly built wheel, installed without
pytest, Chroma, torch or Sentence Transformers. Its actual MCP subprocess starts
from a directory with spaces and no `pyproject.toml` or PYTHONPATH shim, discovers
all eight tools, auto-seeds isolated stores and creates an approval-gated plan.
Real stdio and bearer-authenticated HTTP clients pass on Windows. CI now specifies
Python 3.12/3.14 on Linux/Windows and a manually dispatched real-neural CPU job;
hosted CI and macOS were not executed here. Redis evidence still uses fakeredis.

## Published follow-up: hybrid discovery and persistent review holds

The validated snapshot was pushed as `7dc57ac`; current `main` fixes were then
merged as `0ac7c01`. Both initial snapshots passed hosted CI on Linux/Windows:
[snapshot run](https://github.com/khasim007q/Redacto/actions/runs/41421189240),
[merged-main run](https://github.com/khasim007q/Redacto/actions/runs/41421762424).
The local validation of the subsequent changes is recorded separately in
`benchmarks/published-validation-local.json`; use the pushed head's GitHub checks
for the latest hosted outcome rather than treating an earlier green run as proof.

Hybrid mode retains independently versioned/scored hashing and neural vectors.
It does not average the two signals. It can compare older matching hashing or
pinned neural tombstones by selecting their corresponding component; missing
components or different revisions still report incomplete coverage. Threshold
policy is captured when a plan is created so raising runtime thresholds cannot
silently weaken a previously issued revocation.

Two additional replay/recovery defects were fixed:

1. A record could be flagged for review during discovery yet its exact replay could
   pass ingestion's higher similarity threshold. Tombstones now retain private,
   versioned HMAC risk holds for review-only payloads. Replays are quarantined,
   never promoted to deletion proof. Their key versions participate in rotation
   and fail-closed checks and are omitted from the public tombstone listing.
2. Tombstones previously returned the first apply's snapshot unchanged. Subsequent
   reviewed removals now refresh the same tombstone, preserving previous removals
   and promoting newly removed payloads from quarantine to blocked replay.

Approval, review and cancellation serialize with apply under the same local
boundary. The `main` merge preserves late JSONL appends and recomputes a rewrite
after later changes, while checking the target event's fingerprint on every retry.
Existing databases with an already-present but NULL tombstone length are backfilled
from the retained request, without restoring any plaintext revoked value.

On the unchanged 400-record authored corpus:

| Measurement | Hashing | Neural only | Hybrid |
|---|---:|---:|---:|
| Disclosures discovered | 230/240 | 232/240 | 240/240 |
| False positives held for review | 9 | 1 | 10 |
| Precision | 96.23% | 99.57% | 96.00% |
| Recall | 95.83% | 96.67% | 100.00% |
| Known-record disclosing replays allowed | 10 | 3 | 0 |
| Safe replay quarantines | 9 | 1 | 10 |
| False deletions | 0 | 0 | 0 |

The hybrid split result is 60/60 disclosures found, two false positives, zero
false deletions and zero allowed known-record disclosing replays on 100 records.
These results do **not** establish general semantic recall. Replay uses the same
labelled payloads present before planning, so exact risk holds contribute. Survivor
assessment also includes known review holds. A separate real-model integration
test checks a previously unseen translated reformulation and requires an actual
embedding signal rather than a stored review fingerprint.

**116/240 disclosures remain after approved actions**, because review-only records
are preserved. The full review-held survivor set is now flagged, but those flags
are not an independent proof of semantic absence. Hybrid trades additional review
work for recall. The labelled corpus and its split have already been inspected;
independent external evaluation is still needed.

Reports: `published-hashing-local.json`, `published-neural-local.json`,
`hybrid-local.json`, `hybrid-holdout-local.json`, `published-reference-local.json`.
The persistent application journey still preserves public context and allowed
summary content, refuses guarded replay, filters bypass retrieval and reports two
direct bypasses. The final runtime-only wheel and real stdio/HTTP MCP transports
were rechecked. The compatibility matrix now includes macOS and a separate real
Redis server job; a manually dispatched job evaluates real CPU neural/hybrid models.

## Selective cleanup and simpler integration (2026-11-02)

Mixed records containing matching source passages now offer reviewed span edits,
including confirmed descendants whose other content should survive. Plans retain
only keyed span fingerprints/lengths, show the preservation option and bind it to
the approved version. `review-item --action redact` selects the edit;
`--action delete` explicitly selects whole-record removal. Default approval uses
an available planned edit. Optional allowed-parent regeneration still takes
precedence. Suspected relationships remain suspected after review.

JSONL edits operate on decoded nested strings, including escaped quotes, while
preserving event identity and other values. Ambiguous duplicate keys, colliding
rewritten keys and identity-changing edits fail without replacing the log. A
missing span in a still-present record is an action failure rather than a false
claim that the record is already absent. Changed fingerprints prevent stale edits.

`setup` creates one strict saved profile and prints a local MCP client entry.
Ordinary folders need no Python project file. Files-only profiles exclude unused
stores explicitly; managed profiles add owned SQLite memory/cache and JSONL stores.
Demo seeding is explicit. Private state stays outside scanned documents, unknown
state/scope conflicts are refused, and reruns preserve keys and stores. Profiles
ignore ambient scope/key overrides and launch-directory `.env` files. `doctor`
reports missing stores, unavailable graph state and degraded tombstone protection.

`WorkspaceClient` shares the profile with MCP and operator commands, checks current
sources before dependent writes, guards admission/retrieval and records instrumented
lineage. Content and graph writes remain separate persistence operations; failures
report known/uncertain write status for reconciliation. Direct writers remain
possible. The [setup guide](workspace-setup.md) includes the interview workflow,
application example and exact boundaries.

Final local validation: 409 passed/2 skipped on Windows Python 3.12 with actual
pinned CPU neural/hybrid integration; 407 passed/4 skipped on Python 3.14. There are
34 new capability regression cases. A rebuilt runtime-only wheel passed the new
profile stdio journey (separate CLI approval, apply, verify, public preservation and
replay refusal) outside the repository with spaces and no `pyproject.toml`, as well
as legacy stdio and authenticated HTTP smoke tests. The persistent Chroma app now
reviews/redacts mixed query logs, regenerates its mixed summary, preserves public
context and detects two deliberate bypasses. Its final clean scoped receipt follows
the explicit review step. The unchanged hashing corpus still finds 230/240
disclosures, leaves 116 review-held disclosures and allows ten disclosing replays;
this iteration makes no new general semantic-recall claim.

Machine-readable evidence: `benchmarks/capabilities-validation-local.json` and
`benchmarks/capabilities-reference-local.json`. CI now exercises the profile MCP
journey across the OS/Python matrix and in the runtime-only install job. Hosted
results must be checked against the new commit rather than inferred from earlier
green runs.
