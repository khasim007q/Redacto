"""Optional local neural embeddings with pinned weights and bounded inference.

No record is sent to an inference service. Model downloads occur only when this
provider is explicitly selected and offline mode is disabled. Remote model code
and pickle weights are disabled. Similarity remains advisory.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import OrderedDict
from functools import lru_cache
from threading import RLock

from redacto.errors import RedactoError

DEFAULT_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
DEFAULT_REVISION = "e8f8c211226b894fcb81acc59f3b34ba3efd5f42"
MAX_CHUNKS = 256
_MODEL_LOCK = RLock()


@lru_cache(maxsize=2)
def _load_model(name: str, revision: str, local_files_only: bool):
    try:
        from sentence_transformers import SentenceTransformer
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        raise RedactoError("embedding_dependency_missing", "Install redacto[semantic] to use neural embeddings.") from exc
    except Exception as exc:
        raise RedactoError("embedding_dependency_unavailable", "The neural dependencies could not initialize; check the CPU runtime installation.") from exc
    try:
        # Resolve the immutable Hub snapshot explicitly. Otherwise a same-named
        # directory in the client's cwd could override a remote model identifier.
        snapshot = snapshot_download(repo_id=name, revision=revision, local_files_only=local_files_only,
                                     allow_patterns=["*.json", "*.safetensors", "*.txt", "*.model"])
        return SentenceTransformer(
            snapshot, revision=revision, device="cpu", trust_remote_code=False,
            local_files_only=True, model_kwargs={"use_safetensors": True},
        )
    except Exception as exc:
        # Provider tracebacks can contain paths, credentials or source snippets.
        raise RedactoError("embedding_model_unavailable", "The configured embedding model could not be loaded; no fallback was substituted.") from exc


class SentenceTransformerEmbeddingProvider:
    def __init__(self, *, model: str = DEFAULT_MODEL, revision: str = DEFAULT_REVISION,
                 local_files_only: bool = False):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", model or "") or not re.fullmatch(r"[a-fA-F0-9]{40}", revision):
            raise RedactoError("invalid_configuration", "Neural embeddings require an organization/model Hub ID and an immutable 40-character commit revision.")
        self.model_id = f"sentence-transformers:{model}@{revision.lower()}:chunk-mean-v1"
        self._name = model
        self._revision = revision.lower()
        self._offline = local_files_only
        self._cache: OrderedDict[str, tuple[float, ...]] = OrderedDict()
        self._lock = RLock()

    def embed(self, text: str) -> list[float]:
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with self._lock, _MODEL_LOCK:
            if digest in self._cache:
                self._cache.move_to_end(digest)
                return list(self._cache[digest])
            model = _load_model(self._name, self._revision, self._offline)
            try:
                # Explicit token windows cover the tail of long records instead
                # of silently accepting the model's normal prefix truncation.
                tokens = model.tokenizer.encode(text, add_special_tokens=False, truncation=False)
                window = min(int(model.max_seq_length), 512) - model.tokenizer.num_special_tokens_to_add(pair=False)
                if window < 8:
                    raise ValueError("invalid token window")
                step = window - min(32, window // 4)
                starts = list(range(0, max(1, len(tokens) - window + step), step))
                if len(starts) > MAX_CHUNKS:
                    raise RedactoError("embedding_input_too_large", "Record exceeds the neural embedding window budget; it was not assessed.")
                chunks = [model.tokenizer.decode(tokens[start:start + window], skip_special_tokens=True) for start in starts]
                if any(len(model.tokenizer.encode(chunk, add_special_tokens=False, truncation=False)) > window for chunk in chunks):
                    raise RedactoError("embedding_input_unassessed", "Token windows could not be encoded without truncation; the record was not assessed.")
                rows = model.encode(chunks, normalize_embeddings=True, convert_to_numpy=True,
                                    show_progress_bar=False, batch_size=16)
                dimension = int(model.get_embedding_dimension())
                vectors = [[float(value) for value in row] for row in rows]
                if len(vectors) != len(chunks) or not dimension or any(
                    len(row) != dimension or not all(math.isfinite(value) for value in row) for row in vectors
                ):
                    raise ValueError("invalid embedding shape or values")
                vector = [sum(row[i] for row in vectors) / len(vectors) for i in range(dimension)]
                norm = math.sqrt(sum(value * value for value in vector))
                if not math.isfinite(norm) or norm == 0:
                    raise ValueError("invalid embedding norm")
                vector = [value / norm for value in vector]
            except RedactoError:
                raise
            except Exception as exc:
                raise RedactoError("embedding_inference_failed", "Neural embedding inference failed; no clean result or fallback was returned.") from exc
            # Cache vectors by a digest, never the plaintext as an lru_cache key.
            self._cache[digest] = tuple(vector)
            if len(self._cache) > 256:
                self._cache.popitem(last=False)
            return vector
