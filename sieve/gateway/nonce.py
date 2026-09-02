"""Single-use nonce enforcement, backed by SQLite.

Defeats replay (attack A1) and — because the reserve is atomic — holds under
concurrent duplicate submission (attack C11). The atomicity is not incidental:
it is the SQLite `INSERT` against a `PRIMARY KEY`. Two racing callers with the
same nonce both attempt the insert; exactly one succeeds, the other hits the
uniqueness constraint and is told the nonce is already used. The database is the
serialisation point, so there is no application-level lock to get wrong.

An in-memory implementation is provided for tests that do not need durability,
but the concurrency tests deliberately use the SQLite one, because an in-memory
dict guarded by the GIL would prove nothing about real contention.
"""

from __future__ import annotations

import sqlite3
import threading


class SqliteNonceStore:
    """WAL-mode SQLite nonce store. Safe across threads and processes.

    The connection is opened per-store; callers in different threads each get
    their own via the check_and_reserve path, which opens a short-lived
    connection so the store matches how the gateway actually runs (a request per
    thread), rather than sharing one connection and hiding the contention.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._init_lock = threading.Lock()
        with self._init_lock:
            conn = self._connect()
            try:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS nonces ("
                    "  nonce TEXT PRIMARY KEY,"
                    "  reserved_at_ns INTEGER NOT NULL"
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

    def check_and_reserve(self, nonce: str) -> bool:
        """Atomically reserve `nonce`. True if it was fresh, False if already used.

        The whole decision is the single INSERT. We do not SELECT-then-INSERT:
        that read-modify-write is exactly the race attack C11 exploits.
        """
        import time

        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO nonces (nonce, reserved_at_ns) VALUES (?, ?)",
                (nonce, time.perf_counter_ns()),
            )
            return True
        except sqlite3.IntegrityError:
            # PRIMARY KEY violation: someone reserved it first. That someone may
            # be a millisecond ahead of us in a genuine race — which is the point.
            return False
        finally:
            conn.close()


class InMemoryNonceStore:
    """Thread-safe in-memory store for tests that do not exercise real
    contention. Uses a lock so it is at least internally consistent, but it is
    not what the concurrency tests run against."""

    def __init__(self) -> None:
        self._used: set[str] = set()
        self._lock = threading.Lock()

    def check_and_reserve(self, nonce: str) -> bool:
        with self._lock:
            if nonce in self._used:
                return False
            self._used.add(nonce)
            return True
