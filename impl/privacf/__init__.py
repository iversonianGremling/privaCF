"""PrivaCF reference implementation — Experiment E1 (collaborative-filtering core).

This package implements the §3 collaborative-filtering core of the PrivaCF spec
(SPEC.md) and Experiment E1 from §9.1: "Does it recommend at all?".

Scope (E1 only): the local, offline CF computation. No crypto, network, mixnet,
or blockchain — those are Phases 1–3 of §9.2 and later experiments. E1 tests the
core hypothesis that item-based CF over accumulated gossip vectors surfaces
long-tail content a popularity baseline misses.

Spec → code map:
  §3.2 item-based CF (cosine sim, score = Σ sim·weight)   -> cf.ItemCF
  §3.4 trust_contribution / trust_total / item_weight      -> cf.ItemCF._build
  §3.5 dislike-aware scoring                                -> cf.ItemCF.score_all
  §3.7 novelty / diversity                                  -> cf.ItemCF._build
  §9.1 E1 + §9.3 metrics (P@K, NDCG, long-tail discovery)   -> metrics, experiment
  popularity baseline                                       -> baseline.Popularity
"""

__all__ = ["data", "cf", "baseline", "metrics", "experiment"]
