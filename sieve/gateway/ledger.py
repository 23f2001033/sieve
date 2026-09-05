"""Hash-chained, append-only audit ledger.

Every decision the gateway makes — allow or refuse — is written here, and each
entry's hash includes the previous entry's hash. That chaining is what makes the
log *tamper-evident*: change any past entry and every hash after it stops
matching, so the verifier can name the exact sequence number where the chain
first breaks.

An honest boundary, stated plainly here and in docs/LIMITS.md: this is
tamper-EVIDENT, not tamper-PROOF. Anyone with write access to the database can
recompute the whole chain forward from their edit and leave it internally
consistent. Making it a true external witness would require anchoring the head
hash somewhere the attacker cannot also rewrite (a public append-only log). That
is deliberately out of scope for a single-node build; what is in scope is that
*undetectable* tampering requires rewriting every subsequent entry, and the
verifier proves the chain is intact against its recorded head.

The genesis entry has a fixed, well-known previous hash so an empty ledger has a
defined head and cannot be confused with a truncated one.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from typing import Any

from sieve.contracts.canonical import canonical_digest
from sieve.gateway.crypto import SigningKey, verify_signature

GENESIS_PREV_HASH = "0" * 64
DOMAIN_LEDGER_SIG = "ledger-signature"


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    seq: int
    prev_hash: str
    entry_hash: str
    kind: str  # "allow" | "refuse"
    body: dict[str, Any]
    signature: str | None = None  # hex Ed25519 sig by the gateway key, if signed

    def to_json(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "kind": self.kind,
            "body": self.body,
            "signed": self.signature is not None,
        }


def _sig_body(seq: int, entry_hash: str) -> dict[str, Any]:
    """What the gateway key signs for an entry. Binding the seq as well as the
    hash means a signature cannot be lifted from one position to another."""
    return {"seq": seq, "entry_hash": entry_hash}


@dataclass(frozen=True, slots=True)
class IntegrityResult:
    """The output of a full-chain verification — what the UI's integrity button
    renders."""

    valid: bool
    entries_checked: int
    head_hash: str
    broken_at_seq: int | None = None
    detail: str = "chain intact"

    def to_json(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "entries_checked": self.entries_checked,
            "head_hash": self.head_hash,
            "broken_at_seq": self.broken_at_seq,
            "detail": self.detail,
        }


def compute_entry_hash(seq: int, prev_hash: str, kind: str, body: dict[str, Any]) -> str:
    """The hash bound into an entry. Uses the canonical digest so the same body
    always hashes identically regardless of key order — the ledger inherits the
    injectivity property from the signing layer."""
    return canonical_digest(
        "ledger-entry",
        {"seq": seq, "prev_hash": prev_hash, "kind": kind, "body": body},
    ).hex()


class SqliteLedger:
    """Append-only hash-chained ledger in SQLite.

    Appends are serialised by a process-local lock so the chain head is read and
    extended atomically. (Across processes the design would move the head into a
    row updated under a transaction; single-node is the documented scope.)
    """

    def __init__(self, db_path: str, *, signing_key: SigningKey | None = None) -> None:
        self._db_path = db_path
        self._append_lock = threading.Lock()
        # When a signing key is present, every entry is signed and verify() checks
        # the signature. This is the difference between tamper-EVIDENT and
        # tamper-RESISTANT: a hash chain can be recomputed forward by anyone with
        # database write access, but a valid signature cannot be forged without
        # this key. See docs/LIMITS.md.
        self._signing_key = signing_key
        self._verify_key_hex = signing_key.public_hex if signing_key else None
        conn = self._connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS ledger ("
                "  seq INTEGER PRIMARY KEY,"
                "  prev_hash TEXT NOT NULL,"
                "  entry_hash TEXT NOT NULL,"
                "  kind TEXT NOT NULL,"
                "  body_json TEXT NOT NULL,"
                "  signature TEXT"
                ")"
            )
            conn.commit()
        finally:
            conn.close()

    @property
    def verify_key_hex(self) -> str | None:
        return self._verify_key_hex

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def append(self, kind: str, body: dict[str, Any]) -> LedgerEntry:
        with self._append_lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                if row is None:
                    seq, prev_hash = 0, GENESIS_PREV_HASH
                else:
                    seq, prev_hash = row[0] + 1, row[1]

                entry_hash = compute_entry_hash(seq, prev_hash, kind, body)
                signature = None
                if self._signing_key is not None:
                    signature = self._signing_key.sign(
                        DOMAIN_LEDGER_SIG, _sig_body(seq, entry_hash)).hex()
                conn.execute(
                    "INSERT INTO ledger (seq, prev_hash, entry_hash, kind, body_json, "
                    "signature) VALUES (?, ?, ?, ?, ?, ?)",
                    (seq, prev_hash, entry_hash, kind, json.dumps(body), signature),
                )
                return LedgerEntry(
                    seq=seq,
                    prev_hash=prev_hash,
                    entry_hash=entry_hash,
                    kind=kind,
                    body=body,
                    signature=signature,
                )
            finally:
                conn.close()

    def entries(self) -> list[LedgerEntry]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT seq, prev_hash, entry_hash, kind, body_json, signature "
                "FROM ledger ORDER BY seq ASC"
            ).fetchall()
        finally:
            conn.close()
        return [
            LedgerEntry(
                seq=r[0],
                prev_hash=r[1],
                entry_hash=r[2],
                kind=r[3],
                body=json.loads(r[4]),
                signature=r[5],
            )
            for r in rows
        ]

    def verify(self) -> IntegrityResult:
        """Recompute the whole chain and report the first break, if any.

        Two ways an entry can be corrupt, and both are caught:
          - its recorded hash no longer matches its own recomputed contents
            (someone edited the body);
          - its prev_hash does not match the actual previous entry's hash
            (someone deleted, reordered, or inserted an entry).
        """
        entries = self.entries()
        expected_prev = GENESIS_PREV_HASH

        for index, entry in enumerate(entries):
            if entry.seq != index:
                return IntegrityResult(
                    valid=False,
                    entries_checked=index,
                    head_hash=expected_prev,
                    broken_at_seq=entry.seq,
                    detail=f"sequence gap: expected seq {index}, found {entry.seq}",
                )

            if entry.prev_hash != expected_prev:
                return IntegrityResult(
                    valid=False,
                    entries_checked=index,
                    head_hash=expected_prev,
                    broken_at_seq=entry.seq,
                    detail=(
                        f"entry {entry.seq} chains to {entry.prev_hash[:12]}… but the "
                        f"previous entry hashes to {expected_prev[:12]}…"
                    ),
                )

            recomputed = compute_entry_hash(
                entry.seq, entry.prev_hash, entry.kind, entry.body
            )
            if recomputed != entry.entry_hash:
                return IntegrityResult(
                    valid=False,
                    entries_checked=index,
                    head_hash=expected_prev,
                    broken_at_seq=entry.seq,
                    detail=(
                        f"entry {entry.seq} body has been altered: stored hash "
                        f"{entry.entry_hash[:12]}… but recomputes to {recomputed[:12]}…"
                    ),
                )

            # Signature check. This is what a recomputed-forward rewrite cannot
            # survive: an attacker with DB write can fix every hash to be
            # internally consistent, but cannot produce a valid signature over the
            # tampered entry without the gateway key.
            if self._verify_key_hex is not None:
                ok = entry.signature is not None and verify_signature(
                    self._verify_key_hex, DOMAIN_LEDGER_SIG,
                    _sig_body(entry.seq, entry.entry_hash),
                    bytes.fromhex(entry.signature),
                )
                if not ok:
                    return IntegrityResult(
                        valid=False,
                        entries_checked=index,
                        head_hash=expected_prev,
                        broken_at_seq=entry.seq,
                        detail=(
                            f"entry {entry.seq} is not validly signed by the gateway "
                            f"key — the chain was rewritten without it"
                        ),
                    )

            expected_prev = entry.entry_hash

        return IntegrityResult(
            valid=True,
            entries_checked=len(entries),
            head_hash=expected_prev,
            detail=f"chain intact across {len(entries)} entries",
        )
