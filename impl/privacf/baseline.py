"""Popularity baseline — the comparison E1 must beat on long-tail discovery (§9.1)."""

from __future__ import annotations

import numpy as np


class Popularity:
    """Recommends the globally most-popular unseen items. By construction it does
    well on head items and poorly on the long tail — the gate is that CF beats it
    on long-tail discovery."""

    def __init__(self):
        self.pop: np.ndarray | None = None

    def fit(self, seen: np.ndarray) -> "Popularity":
        self.pop = seen.sum(axis=0).astype(np.float32)
        return self

    def score_all(self, seen: np.ndarray) -> np.ndarray:
        assert self.pop is not None
        scores = np.broadcast_to(self.pop, seen.shape).astype(np.float32).copy()
        scores[seen] = -np.inf
        return scores
