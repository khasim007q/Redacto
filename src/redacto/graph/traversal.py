"""Bounded provenance traversal.

`READ_FROM` is exposure evidence, never proof of derivation. Only paths made of
confirmable, non-weak edges count as confirmed descendants for destructive
policy; anything touched through a weak edge is reported separately.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from redacto.graph.repository import Repository

CONFIRMABLE_EVIDENCE = {"instrumented", "imported_metadata", "human_verified"}
WEAK_RELATIONS = {"READ_FROM"}
NON_DERIVATION_RELATIONS = {"STORED_IN"}


@dataclass
class Descendant:
    record_id: str
    depth: int
    via: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "depth": self.depth,
            "via": self.via,
        }


@dataclass
class TraversalResult:
    descendants: list[Descendant]
    exposures: list[Descendant]
    candidates: list[dict[str, Any]]
    max_depth_reached: int

    def descendant_ids(self) -> set[str]:
        return {node.record_id for node in self.descendants}

    def exposure_ids(self) -> set[str]:
        return {node.record_id for node in self.exposures}


def traverse(
    repo: Repository, source_id: str, *, max_depth: int = 3
) -> TraversalResult:
    edges = [
        edge
        for edge in repo.all_lineage_edges()
        if edge["status"] == "confirmed" and edge["evidence_type"] in CONFIRMABLE_EVIDENCE
    ]
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        adjacency.setdefault(edge["source_id"], []).append(edge)

    # best[node] = (depth, strong_path, path_edges)
    best: dict[str, tuple[int, bool, list[dict[str, Any]]]] = {source_id: (0, True, [])}
    queue: deque[str] = deque([source_id])
    max_reached = 0

    while queue:
        node = queue.popleft()
        depth, strong, path = best[node]
        if depth >= max_depth:
            continue
        for edge in adjacency.get(node, []):
            target = edge["target_id"]
            if target == source_id:
                continue
            relation = edge["relation"]
            if relation in NON_DERIVATION_RELATIONS:
                continue
            next_depth = depth + 1
            next_strong = strong and relation not in WEAK_RELATIONS
            next_path = path + [
                {
                    "edge_id": edge["edge_id"],
                    "relation": relation,
                    "evidence_type": edge["evidence_type"],
                }
            ]
            current = best.get(target)
            improved = current is None or (
                (next_strong and not current[1]) or (next_strong == current[1] and next_depth < current[0])
            )
            if improved:
                best[target] = (next_depth, next_strong, next_path)
                max_reached = max(max_reached, next_depth)
                queue.append(target)

    descendants: list[Descendant] = []
    exposures: list[Descendant] = []
    for record_id, (depth, strong, path) in best.items():
        if record_id == source_id:
            continue
        node = Descendant(record_id=record_id, depth=depth, via=path)
        (descendants if strong else exposures).append(node)

    descendants.sort(key=lambda n: (n.depth, n.record_id))
    exposures.sort(key=lambda n: (n.depth, n.record_id))
    return TraversalResult(
        descendants=descendants,
        exposures=exposures,
        candidates=repo.candidate_edges(source_id),
        max_depth_reached=max_reached,
    )
