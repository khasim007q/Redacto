# Optional local multilingual discovery

Redacto defaults to `local_hashing`, a small deterministic lexical provider.
The `semantic` extra adds Sentence Transformers on CPU. It supplements exact,
lineage and disclosure heuristics with a multilingual learned representation.
It does not change approval policy: similarity only proposes review or quarantine.
Credential targets use exact/normalized matching, not semantic similarity.

## Install and check

From the existing Redacto installation on Windows:

```powershell
uv sync --frozen --extra semantic --python 3.12
$env:REDACTO_EMBEDDING_PROVIDER = "hybrid"
$env:REDACTO_EMBEDDING_CANDIDATE_THRESHOLD = "0.55"
$env:REDACTO_EMBEDDING_QUARANTINE_THRESHOLD = "0.60"
.\.venv\Scripts\python.exe -m redacto check-embeddings
```

Add `--extra chroma --extra redis --extra dev` when those features are needed;
`uv sync` removes extras that are not selected. No GPU, inference API key or
running model service is needed. First use downloads pinned public model files;
inference happens locally and record contents are not sent to a model endpoint.
The public model download may contact Hugging Face and its file hosting service.
After the check succeeds, offline mode disables model downloads:

```powershell
$env:REDACTO_EMBEDDING_LOCAL_FILES_ONLY = "true"
.\.venv\Scripts\python.exe -m redacto check-embeddings --offline
```

For Claude Desktop/Code, put the four `REDACTO_EMBEDDING_*` settings above in
the existing MCP server's `env` object and restart the server. Shell variables
set after Claude starts do not configure that already-running server. Its
absolute Python path must point at the environment with the semantic extra.
No `pyproject.toml` is needed in the folders being scanned.

The built-in model is
[`sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2),
revision `e8f8c211226b894fcb81acc59f3b34ba3efd5f42`, with 384-dimensional
vectors. Custom models require both `REDACTO_EMBEDDING_MODEL` and an immutable
40-character `REDACTO_EMBEDDING_REVISION`. Remote model code and pickle weights
are disabled. The [Sentence Transformers API](https://www.sbert.net/docs/package_reference/sentence_transformer/model.html)
documents the revision, offline, device and remote-code options.

`hybrid` retains both the pinned neural model and the existing hashing signal.
Use `sentence_transformers` for neural-only discovery. Both use the same optional
installation. Hybrid is useful when recall matters more than additional review
holds; neural-only can have fewer false positives on this synthetic corpus.

The dependency lock uses the [PyTorch CPU index configuration](https://docs.astral.sh/uv/guides/integration/pytorch/)
on Linux/Windows. Plain `pip install '.[semantic]'` does not read uv's index
configuration; select a CPU PyTorch build explicitly if installing with pip on Linux.

## What changes

- Text is encoded with the pinned learned model, rather than the hashing concept map.
- Hybrid stores two named component spaces in a versioned 896-value vector (512
  hashing + 384 neural for the built-in model). Scores are computed separately,
  never by averaging or taking a cosine over the concatenated vector. Either
  signal may propose review; neither authorizes deletion. Lexical thresholds stay
  at 0.25 for discovery and 0.30 for quarantine and have separate optional settings.
- Long records use overlapping token windows. The window vectors are averaged and
  normalized; no prefix-only truncation is accepted. More than 256 windows or an
  unsafe re-tokenization produces an explicit error, not a clean assessment.
- Similarity thresholds are provider-specific. The initial neural settings are
  0.55 for discovery and 0.60 for quarantine. Explicit `.env`/MCP threshold values
  override the defaults, so replace the hashing thresholds when switching providers.
- Model-load/inference failures are reported without silently substituting another
  embedding space. Stop/retry the operation after correcting the dependency/cache.
- Vectors from different models or revisions are not compared. Such gaps are
  reported by status, ingestion and verification. Original keyed checks still run.
- Upgrading to hybrid preserves comparisons with older hashing or identical pinned
  neural tombstones by selecting their matching component. Downgrading a hybrid
  tombstone to one component reports incomplete coverage. Already-issued policy
  thresholds are retained; raising runtime thresholds does not weaken old holds.
- Exact replays of review-held records remain quarantined using versioned keyed
  fingerprints, even when their score is below the ingestion threshold. These
  fingerprints are private evidence and never prove lineage or authorize deletion.
  Subsequent approved removals refresh the existing tombstone and promote those
  removed fingerprints to blocked replay without discarding earlier protection.
- The optional assessor receives a minimized target alongside each candidate.
  It cannot dismiss an existing unresolved deterministic disclosure signal.

The reference application's retrieval index intentionally remains a separately
labelled 512-dimensional hashing collection. Changing the discovery provider does
not migrate an application's retrieval index or authorize writing neural vectors
into it. Existing Chroma collections can still be scanned and invalidated.

## Reproduce the evidence

```powershell
uv sync --frozen --extra dev --extra semantic --python 3.12
$env:OMP_NUM_THREADS = "4"
$env:REDACTO_TEST_NEURAL = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/test_semantic_live.py
.\.venv\Scripts\python.exe -m redacto benchmark --embedding-provider sentence_transformers --local-files-only --out var/neural.json
.\.venv\Scripts\python.exe -m redacto benchmark --embedding-provider sentence_transformers --split holdout --local-files-only --out var/neural-holdout.json
.\.venv\Scripts\python.exe -m redacto benchmark --embedding-provider hybrid --local-files-only --out var/hybrid.json
.\.venv\Scripts\python.exe -m redacto benchmark --embedding-provider hybrid --split holdout --local-files-only --out var/hybrid-holdout.json
```

The real-model test loads the pinned weights and exercises translated discovery,
review-only planning, apply, semantic residual verification and replay quarantine.
It also tests an unseen translation with no recorded review fingerprint, requiring
an actual embedding signal. Known-candidate replay results in the full benchmark
also include exact review holds; they are not a measurement of unseen paraphrases.
Ordinary unit tests stub inference and do not download model files. A manually
dispatched CI job runs the actual model on Windows and Linux; a configured job
is not evidence that a hosted run passed.

The 400-record corpus is synthetic, with authored labels and a pre-existing
scenario split. It is not an independent or blinded evaluation. Final measured
results and remaining failures are recorded in the audit remediation report.
An embedding score is not a probability or proof of derivation. Multilingual
coverage, transformed facts and mixed-source records remain incomplete; pooled
vectors can dilute a small disclosure within unrelated context. Embeddings are
sensitive derived data and may reveal information; protect the graph database
and its backups. A similarity match never independently authorizes destruction.
