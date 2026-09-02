"""Exactly-once semantics under retry, backed by SQLite.

This is the piece that separates a system that *claims* it cannot double-charge
from one that *demonstrates* it. Two distinct requirements live here, and they
pull in opposite directions:

  - Attack C11 (double-spend): two concurrent submissions of the SAME
    idempotency key must result in exactly ONE charge.
  - Benign case (legitimate retry after a timeout): a client that never heard
    back and retries with the same key must get the SAME result as the first
    attempt — NOT a refusal. Refusing the honest retry would be a false refusal,
    and false refusals are half the honesty metric this project reports.

Both are served by the same mechanism: the idempotency key is a PRIMARY KEY, and
the first writer to claim it records its outcome. A later caller with that key
does not re-execute — it reads back the stored outcome and returns it verbatim.
So a race yields one execution and one replay; an honest retry yields one
execution and, later, that same result handed back. Same code, both behaviours.

The claim state is deliberate: a key is first *claimed* (in-progress), then
*completed* with its result. A second caller arriving mid-flight must wait for
completion rather than seeing "not found" and executing in parallel — that
window is where a naive implementation double-charges under a real race.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class IdempotentOutcome:
    """The recorded result of the first execution under a key."""

    status: str  # "charged" | "refused"
    payload: dict[str, Any]
    replayed: bool  # True when this was read back rather than freshly executed

    def to_json(self) -> dict[str, Any]:
        return {"status": self.status, "payload": self.payload, "replayed": self.replayed}


class DoubleClaim(Exception):
    """Raised internally when a claim races and loses; callers do not see it."""


class SqliteIdempotencyStore:
    """WAL-mode SQLite idempotency store.

    States per key:
      - absent            -> caller may claim and execute
      - claimed (no result) -> another caller is executing; wait for it
      - completed          -> return the stored outcome as a replay
    """

    def __init__(self, db_path: str, *, wait_timeout_s: float = 30.0) -> None:
        self._db_path = db_path
        self._wait_timeout_s = wait_timeout_s
        self._init_lock = threading.Lock()
        with self._init_lock:
            conn = self._connect()
            try:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS idempotency ("
                    "  key TEXT PRIMARY KEY,"
                    "  status TEXT,"          # NULL while claimed, set on completion
                    "  payload_json TEXT,"
                    "  claimed_at_ns INTEGER NOT NULL,"
                    "  completed_at_ns INTEGER"
                    ")"
                )
                conn.commit()
            finally:
                conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def try_claim(self, key: str) -> bool:
        """Attempt to become the executor for `key`.

        True  -> you claimed it; you must execute and then call `complete`.
        False -> someone else claimed or completed it; call `await_outcome`.

        The atomic INSERT is the whole race resolution. Exactly one concurrent
        caller inserts; the rest get IntegrityError and become waiters.
        """
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO idempotency (key, status, payload_json, claimed_at_ns) "
                "VALUES (?, NULL, NULL, ?)",
                (key, time.perf_counter_ns()),
            )
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def complete(self, key: str, outcome: IdempotentOutcome) -> None:
        """Record the result of the execution you claimed."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE idempotency SET status = ?, payload_json = ?, "
                "completed_at_ns = ? WHERE key = ?",
                (
                    outcome.status,
                    json.dumps(outcome.payload),
                    time.perf_counter_ns(),
                    key,
                ),
            )
        finally:
            conn.close()

    def await_outcome(self, key: str) -> IdempotentOutcome:
        """Block until the claiming caller completes, then return its outcome.

        This is the part a naive store gets wrong. Without it, a second caller
        that finds the key already claimed but not yet completed has no result to
        return, and the tempting fix — execute anyway — is precisely the double
        charge. Here the second caller waits for the first to finish and returns
        its result, marked as a replay.
        """
        deadline = time.monotonic() + self._wait_timeout_s
        while time.monotonic() < deadline:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT status, payload_json FROM idempotency WHERE key = ?",
                    (key,),
                ).fetchone()
            finally:
                conn.close()

            if row is not None and row[0] is not None:
                return IdempotentOutcome(
                    status=row[0],
                    payload=json.loads(row[1]),
                    replayed=True,
                )
            time.sleep(0.002)

        raise TimeoutError(f"idempotency key {key!r} never completed within timeout")

    def lookup(self, key: str) -> IdempotentOutcome | None:
        """Non-blocking read of a completed outcome, for the fast retry path."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT status, payload_json FROM idempotency WHERE key = ? "
                "AND status IS NOT NULL",
                (key,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return IdempotentOutcome(status=row[0], payload=json.loads(row[1]), replayed=True)
