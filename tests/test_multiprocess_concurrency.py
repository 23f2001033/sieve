"""Exactly-once across real OS processes — not just threads.

test_concurrency.py proves exactly-once with 25 threads. That is a genuine race,
but it is one process, so the GIL serialises Python bytecode and a sceptic can
argue the guarantee rides on the GIL rather than on the database.

This test removes that argument. It spawns several independent OS processes — no
shared interpreter, no shared GIL, no shared lock — that all try to claim the SAME
idempotency key against one SQLite file at the same instant. Exactly one succeeds.

That is the whole claim behind exactly-once made concrete: the `UNIQUE` constraint
on the idempotency key IS the serialisation point. Nothing in application code
resolves the race; the database does.
"""

from __future__ import annotations

import time
from concurrent.futures import ProcessPoolExecutor

from sieve.gateway.idempotency import SqliteIdempotencyStore


def _claim_in_a_separate_process(args) -> bool:
    """Runs in a spawned child. Opens its OWN connection to the shared database
    and tries to claim the key at the synchronised start time."""
    db_path, key, start_at = args
    store = SqliteIdempotencyStore(db_path)
    delay = start_at - time.time()
    if delay > 0:
        time.sleep(delay)  # fire together, for a real race
    return store.try_claim(key)


def test_exactly_one_process_claims_a_shared_key(tmp_path):
    db_path = str(tmp_path / "idem.db")
    SqliteIdempotencyStore(db_path)  # create the file + schema in the parent first

    n = 6
    key = "one-key-many-processes"
    # A generous barrier so every child has spawned and is waiting before any fires
    # (process spawn on Windows is slow); correctness holds regardless, the barrier
    # just makes it a genuine simultaneous race rather than a staggered one.
    start_at = time.time() + 4.0

    with ProcessPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(_claim_in_a_separate_process,
                                [(db_path, key, start_at)] * n))

    assert sum(results) == 1, (
        f"expected exactly one process to claim the key, got {sum(results)} "
        f"of {n} — the UNIQUE constraint is not serialising across processes"
    )


def test_distinct_keys_each_claim_across_processes(tmp_path):
    """Different keys are independent: N processes with N distinct keys all claim.
    Confirms the previous test's single winner is real serialisation, not a lock
    that blocks everyone."""
    db_path = str(tmp_path / "idem.db")
    SqliteIdempotencyStore(db_path)

    n = 6
    start_at = time.time() + 4.0
    args = [(db_path, f"key-{i}", start_at) for i in range(n)]
    with ProcessPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(_claim_in_a_separate_process, args))

    assert sum(results) == n, "distinct keys should each be claimable"
