"""MovieLens loading, preference mapping, and train/test split for E1.

No pandas dependency — parsing is stdlib + NumPy only.

Preference mapping (spec §3.4: `p_v[X]` is node v's preference weight for item X;
only positive weights are gossiped, negatives stay local as the dislike set §3.5).
We center ratings: ``p = rating - NEUTRAL``. Positive part -> gossip "like" weight;
negative part -> local "dislike" magnitude.
"""

from __future__ import annotations

import io
import os
import urllib.request
import zipfile
from dataclasses import dataclass

import numpy as np

NEUTRAL = 3.0  # rating center; 4,5 -> like, 1,2 -> dislike, 3 -> neutral

_DATASETS = {
    # name: (zip url, member path inside zip, sep)
    "ml-100k": ("https://files.grouplens.org/datasets/movielens/ml-100k.zip",
                "ml-100k/u.data", "\t"),
    "ml-1m": ("https://files.grouplens.org/datasets/movielens/ml-1m.zip",
              "ml-1m/ratings.dat", "::"),
}


@dataclass
class Dataset:
    """Remapped-to-contiguous-index rating events plus catalog sizes."""
    users: np.ndarray      # int32 [n_events] contiguous user index
    items: np.ndarray      # int32 [n_events] contiguous item index
    ratings: np.ndarray    # float32 [n_events]
    ts: np.ndarray         # int64 [n_events] unix timestamp
    n_users: int
    n_items: int
    name: str


def _cache_path(name: str, data_dir: str) -> str:
    return os.path.join(data_dir, name + ".zip")


def _download(name: str, data_dir: str) -> str:
    url, _, _ = _DATASETS[name]
    os.makedirs(data_dir, exist_ok=True)
    path = _cache_path(name, data_dir)
    if not os.path.exists(path):
        print(f"[data] downloading {url} -> {path}")
        urllib.request.urlretrieve(url, path)
    return path


def load(name: str = "ml-1m", data_dir: str = "data") -> Dataset:
    """Download (cached) and parse a MovieLens dataset into a Dataset."""
    if name not in _DATASETS:
        raise ValueError(f"unknown dataset {name!r}; choose from {list(_DATASETS)}")
    _, member, sep = _DATASETS[name]
    zip_path = _download(name, data_dir)

    raw_u, raw_i, raw_r, raw_t = [], [], [], []
    with zipfile.ZipFile(zip_path) as zf:
        with zf.open(member) as fh:
            for line in io.TextIOWrapper(fh, encoding="latin-1"):
                line = line.strip()
                if not line:
                    continue
                parts = line.split(sep)
                raw_u.append(int(parts[0]))
                raw_i.append(int(parts[1]))
                raw_r.append(float(parts[2]))
                raw_t.append(int(parts[3]))

    users_raw = np.asarray(raw_u, dtype=np.int64)
    items_raw = np.asarray(raw_i, dtype=np.int64)
    ratings = np.asarray(raw_r, dtype=np.float32)
    ts = np.asarray(raw_t, dtype=np.int64)

    # remap original ids to contiguous [0, n) indices
    uniq_u, users = np.unique(users_raw, return_inverse=True)
    uniq_i, items = np.unique(items_raw, return_inverse=True)
    print(f"[data] {name}: {len(ratings):,} events, "
          f"{len(uniq_u):,} users, {len(uniq_i):,} items")
    return Dataset(users.astype(np.int32), items.astype(np.int32), ratings, ts,
                   len(uniq_u), len(uniq_i), name)


@dataclass
class Split:
    """Train preference matrices + held-out positive test items per user.

    pref_pos / pref_neg are dense [n_users, n_items] float32 matrices of *train*
    preference weights (positive gossip weights and |dislike| magnitudes). The
    held-out set ``test_pos`` is the evaluation target: liked items removed from
    training that the recommender should surface.
    """
    pref_pos: np.ndarray
    pref_neg: np.ndarray
    seen: np.ndarray            # bool [n_users, n_items] any train interaction
    test_pos: list[np.ndarray]  # per-user int arrays of held-out liked items
    n_users: int
    n_items: int


def make_split(ds: Dataset, like_threshold: float = 4.0, test_frac: float = 0.2,
               strategy: str = "temporal", min_pos: int = 5,
               seed: int = 0) -> Split:
    """Leave-out split. For each user, hold out ``test_frac`` of their *liked*
    items (rating >= like_threshold) as the test target; the rest become train.

    strategy="temporal" holds out each user's most recent likes (realistic);
    "random" holds out a random subset.
    """
    rng = np.random.default_rng(seed)
    n_users, n_items = ds.n_users, ds.n_items
    pref_pos = np.zeros((n_users, n_items), dtype=np.float32)
    pref_neg = np.zeros((n_users, n_items), dtype=np.float32)
    seen = np.zeros((n_users, n_items), dtype=bool)
    test_pos: list[np.ndarray] = [np.empty(0, dtype=np.int32) for _ in range(n_users)]

    # group event indices by user
    order = np.argsort(ds.users, kind="stable")
    u_sorted = ds.users[order]
    boundaries = np.searchsorted(u_sorted, np.arange(n_users + 1))

    centered_all = ds.ratings - NEUTRAL
    for u in range(n_users):
        idx = order[boundaries[u]:boundaries[u + 1]]
        if idx.size == 0:
            continue
        items_u = ds.items[idx]
        cent_u = centered_all[idx]
        ratings_u = ds.ratings[idx]
        ts_u = ds.ts[idx]

        liked_mask = ratings_u >= like_threshold
        liked_pos = np.where(liked_mask)[0]  # positions within idx

        held = np.empty(0, dtype=int)
        if liked_pos.size >= min_pos:
            n_test = max(1, int(round(test_frac * liked_pos.size)))
            if strategy == "temporal":
                order_lp = liked_pos[np.argsort(ts_u[liked_pos], kind="stable")]
                held = order_lp[-n_test:]
            else:
                held = rng.choice(liked_pos, size=n_test, replace=False)

        held_set = set(held.tolist())
        test_items = []
        for p in range(idx.size):
            it = int(items_u[p])
            if p in held_set:
                test_items.append(it)
                continue  # held out — not in train
            seen[u, it] = True
            c = cent_u[p]
            if c > 0:
                pref_pos[u, it] = max(pref_pos[u, it], c)   # gossip "like"
            elif c < 0:
                pref_neg[u, it] = max(pref_neg[u, it], -c)  # local dislike
        if test_items:
            test_pos[u] = np.asarray(sorted(set(test_items)), dtype=np.int32)

    n_eval = sum(t.size > 0 for t in test_pos)
    print(f"[split] strategy={strategy} test_frac={test_frac} -> "
          f"{n_eval:,} evaluatable users")
    return Split(pref_pos, pref_neg, seen, test_pos, n_users, n_items)


def popularity_segments(seen: np.ndarray, head_frac: float = 0.2):
    """Split items into head / long-tail by train interaction count (§9.3:
    head = top head_frac of the popularity distribution, tail = remainder).

    Returns (is_head bool[n_items], is_tail bool[n_items], pop_count int[n_items]).
    """
    pop = seen.sum(axis=0).astype(np.int64)
    n_items = pop.size
    order = np.argsort(-pop, kind="stable")
    n_head = max(1, int(round(head_frac * n_items)))
    is_head = np.zeros(n_items, dtype=bool)
    is_head[order[:n_head]] = True
    is_tail = ~is_head
    return is_head, is_tail, pop
