# Semantic discovery

Confirmed provenance comes from trusted ingestion/transformations or verified
metadata. Similarity can propose a candidate; it never proves derivation.

Discovery combines normalized keyed fingerprints, passage/shingle overlap,
amount/name heuristics and optional embedding similarity. The default hashing
provider is deterministic lexical similarity, not a language understanding model.
The optional `sentence_transformers` provider uses a pinned multilingual CPU model;
`hybrid` retains separate lexical and neural signals and thresholds.

Install neural dependencies with `uv sync --frozen --extra semantic`. Set the
profile `options` field `REDACTO_EMBEDDING_PROVIDER` to `hybrid` or
`sentence_transformers`, then run `redacto check-embeddings --profile PATH`.
A custom model requires a model name and immutable 40-character revision.
`REDACTO_EMBEDDING_LOCAL_FILES_ONLY=true` forbids downloads after caching weights.
Neural/model failures remain visible; credentials are never embedded.

Candidates above thresholds remain review-required. Review-held payloads can have
private keyed replay holds; replay quarantine does not promote their lineage to
confirmed. Tombstones preserve model identity and captured thresholds. Missing
model components/key versions degrade reported protection rather than silently
changing past policy.

Exact source-passage redaction offers preserve unrelated text only after review.
They are bounded by size, number of passages and window-hashing work. They do not
rewrite paraphrases, translations or transformed facts. Optional regeneration from
allowed parents must pass leakage, extractive grounding and retention checks.

Semantic survivor assessment reports tested coverage and suspected disclosures.
It cannot prove semantic absence. False positives create review work; false negatives
can leave disclosures. Evaluate the actual application before relying on deletion.

Development evaluation: `python tests/run_benchmark.py --out var/benchmark.json`.
The authored 400-record corpus is `tests/data/adversarial-v1.json`. Its dev/holdout
entities differ, but labels/templates have been inspected and are not independently
annotated. Known-record replay holds contribute to replay results. Neither high
corpus recall nor a signed receipt establishes production effectiveness.
