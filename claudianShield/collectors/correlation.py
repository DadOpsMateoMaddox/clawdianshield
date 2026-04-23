from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from runner.models import NormalizedEvent


def build_host_graph(events: List[NormalizedEvent]) -> Dict[str, List[str]]:
    """
    Build source->target host edges from cross-host event details.
    Returns adjacency dict: {source_host: [target_host, ...]}
    """
    graph: Dict[str, List[str]] = defaultdict(list)
    for e in events:
        src = e.details.get("source_host")
        if src and src != e.host:
            if e.host not in graph[src]:
                graph[src].append(e.host)
    return dict(graph)


def cross_host_pairs(events: List[NormalizedEvent]) -> List[tuple[str, str]]:
    graph = build_host_graph(events)
    return [(src, tgt) for src, targets in graph.items() for tgt in targets]
