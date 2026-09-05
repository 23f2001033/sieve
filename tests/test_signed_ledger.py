"""Signed ledger: tamper-resistant, not just tamper-evident.

A plain hash chain is tamper-EVIDENT — but an attacker with database write access
can recompute every hash forward and leave the chain internally consistent,
defeating it. Signing each entry with the gateway key raises the bar: the attacker
can fix the hashes, but cannot forge a signature over the rewritten entry.

These tests prove exactly that: a full forward rewrite passes every hash check and
is still caught by the signature.
"""

from __future__ import annotations

import json
import sqlite3

from sieve.gateway.crypto import SigningKey
from sieve.gateway.ledger import SqliteLedger, compute_entry_hash


def _seed(path, key, n=6):
    ledger = SqliteLedger(path, signing_key=key)
    for i in range(n):
        ledger.append("allow", {"i": i, "amount_paise": 100_00})
    return ledger


def test_signed_ledger_verifies_clean(tmp_path):
    key = SigningKey.generate()
    ledger = _seed(str(tmp_path / "l.db"), key)
    result = ledger.verify()
    assert result.valid
    assert ledger.verify_key_hex == key.public_hex


def test_naive_body_edit_is_caught_by_the_hash(tmp_path):
    key = SigningKey.generate()
    path = str(tmp_path / "l.db")
    ledger = _seed(path, key)
    conn = sqlite3.connect(path)
    conn.execute("UPDATE ledger SET body_json = ? WHERE seq = 2",
                 (json.dumps({"i": 2, "amount_paise": 999999_00}),))
    conn.commit(); conn.close()
    r = ledger.verify()
    assert not r.valid
    assert r.broken_at_seq == 2


def test_full_forward_rewrite_is_caught_by_the_signature(tmp_path):
    """The sophisticated attack a plain hash chain cannot stop. Edit entry 2 and
    recompute every hash forward so the chain is internally consistent — then the
    ONLY thing that catches it is the signature."""
    key = SigningKey.generate()
    path = str(tmp_path / "l.db")
    ledger = _seed(path, key, n=6)
    assert ledger.verify().valid

    conn = sqlite3.connect(path)
    rows = conn.execute(
        "SELECT seq, entry_hash, kind, body_json FROM ledger ORDER BY seq").fetchall()
    prev = rows[1][1]  # entry 1's hash, unchanged
    for seq, _h, kind, body_json in rows[2:]:
        body = json.loads(body_json)
        if seq == 2:
            body = {"i": 2, "amount_paise": 999999_00}
        new_hash = compute_entry_hash(seq, prev, kind, body)
        conn.execute("UPDATE ledger SET prev_hash=?, entry_hash=?, body_json=? WHERE seq=?",
                     (prev, new_hash, json.dumps(body), seq))
        prev = new_hash
    conn.commit(); conn.close()

    r = ledger.verify()
    assert not r.valid, "a forward-rewritten chain slipped past verification"
    assert r.broken_at_seq == 2
    assert "signed" in r.detail or "signature" in r.detail, r.detail


def test_an_unsigned_ledger_is_still_tamper_evident(tmp_path):
    """Backwards compatible: without a key, the ledger still catches naive edits
    via the hash chain — it just cannot resist a full forward rewrite."""
    path = str(tmp_path / "l.db")
    ledger = SqliteLedger(path)  # no signing key
    for i in range(4):
        ledger.append("allow", {"i": i})
    assert ledger.verify().valid
    conn = sqlite3.connect(path)
    conn.execute("UPDATE ledger SET body_json = ? WHERE seq = 1", (json.dumps({"i": 99}),))
    conn.commit(); conn.close()
    assert not ledger.verify().valid


def test_signature_cannot_be_lifted_to_another_position(tmp_path):
    """The signature binds the seq, so copying entry 3's signature onto entry 4
    does not validate."""
    key = SigningKey.generate()
    path = str(tmp_path / "l.db")
    ledger = _seed(path, key, n=6)
    conn = sqlite3.connect(path)
    sig3 = conn.execute("SELECT signature FROM ledger WHERE seq = 3").fetchone()[0]
    conn.execute("UPDATE ledger SET signature = ? WHERE seq = 4", (sig3,))
    conn.commit(); conn.close()
    r = ledger.verify()
    assert not r.valid
    assert r.broken_at_seq == 4
