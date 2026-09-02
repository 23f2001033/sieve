"""The reference gateway — the product. Implements GatewayAdapter.

This is the single choke point every money action passes through, assembled from
the pieces already built and tested: the policy engine, the nonce and
idempotency stores, the hash-chained ledger, and the catalog. It adds the two
things those pieces cannot provide individually:

  1. **Idempotency wrapping.** `submit` claims the intent's idempotency key; the
     winner of that claim executes the decision, everyone else replays its
     outcome. This is what makes a concurrent retry charge exactly once and an
     honest retry get the same answer rather than a refusal.

  2. **Cumulative spend, atomically.** The budget check needs to know what has
     already been committed under an intent's root authority, and the
     check-and-commit must be atomic against other orders on the same authority
     — otherwise two concurrent orders each see the old total and both pass. A
     per-gateway lock guards authorise-and-commit. Single-node by design; see
     docs/LIMITS.md for what production scale-out requires.

No LLM is reachable from here. `tests/test_no_llm_in_policy.py` includes this
module in the guarded path.
"""

from __future__ import annotations

import threading
from dataclasses import replace

from sieve.contracts.mandate import Intent
from sieve.contracts.verdict import ReasonCode, Verdict
from sieve.gateway.idempotency import IdempotentOutcome, SqliteIdempotencyStore
from sieve.gateway.inventory import Northlight
from sieve.gateway.ledger import SqliteLedger
from sieve.gateway.nonce import SqliteNonceStore
from sieve.gateway.policy import Clock, evaluate


class SieveGateway:
    name = "SIEVE (reference)"

    def __init__(
        self,
        *,
        catalog: Northlight,
        nonce_store: SqliteNonceStore,
        idempotency_store: SqliteIdempotencyStore,
        ledger: SqliteLedger,
        clock: Clock,
        merchant_id: str,
        trusted_roots: frozenset[str],
        revoked_keys: frozenset[str] = frozenset(),
        payments=None,
    ) -> None:
        from sieve.gateway.razorpay import NullRail

        self._catalog = catalog
        self._nonces = nonce_store
        self._idem = idempotency_store
        self._ledger = ledger
        self._clock = clock
        self._merchant_id = merchant_id
        self._trusted_roots = trusted_roots
        self._revoked_keys = revoked_keys
        # The payment rail is reached at exactly one point: after ALLOW. A
        # refusal never produces a call, and the ledger records that it didn't.
        self._payments = payments or NullRail()

        # Cumulative spend per root authority. In-memory and lock-guarded: the
        # single-node serialisation point for the budget invariant.
        self._spent: dict[str, int] = {}
        self._commit_lock = threading.Lock()

    def submit(self, intent: Intent) -> Verdict:
        key = intent.idempotency_key

        # Idempotency: exactly-once execution per key.
        if self._idem.try_claim(key):
            verdict = self._authorise_and_commit(intent)
            self._idem.complete(
                key,
                IdempotentOutcome(
                    status="charged" if verdict.allowed else "refused",
                    payload=verdict.to_json(),
                    replayed=False,
                ),
            )
            return verdict

        # Lost the claim: another caller is (or was) executing this exact key.
        # Wait for and replay their verdict rather than re-deciding. The replayed
        # verdict is marked so a caller (and the concurrency attack) can tell a
        # fresh charge from a replay of one — exactly-once means one fresh charge,
        # N-1 replays.
        outcome = self._idem.await_outcome(key)
        verdict = _verdict_from_payload(outcome.payload)
        return replace(verdict, evidence={**verdict.evidence, "replayed": True})

    def _authorise_and_commit(self, intent: Intent) -> Verdict:
        # The budget check reads spent, and on ALLOW the commit increments it.
        # Both happen under one lock so two concurrent orders on the same
        # authority cannot both see the pre-order total.
        with self._commit_lock:
            root = intent.root if intent.chain else ""
            spent = self._spent.get(root, 0)

            verdict = evaluate(
                intent,
                catalog=self._catalog,
                nonce_store=self._nonces,
                clock=self._clock,
                merchant_id=self._merchant_id,
                trusted_roots=self._trusted_roots,
                revoked_keys=self._revoked_keys,
                spent_paise=spent,
            )

            if verdict.allowed:
                total = verdict.evidence["total_paise"]
                self._spent[root] = spent + total
                # Money moves only here — downstream of the verdict, never before.
                order = self._payments.create_order(
                    amount_paise=total,
                    receipt=intent.idempotency_key[:40],
                    notes={"merchant": intent.merchant_id, "agent": intent.signer[:16]},
                )
                verdict = replace(
                    verdict,
                    evidence={**verdict.evidence, "razorpay": order.to_json()},
                )
                body = intent_ledger_body(intent, verdict)
                body["razorpay"] = order.to_json()
                self._ledger.append("allow", body)
            else:
                body = intent_ledger_body(intent, verdict)
                # Recorded explicitly rather than omitted: the absence of a
                # payment call is itself evidence worth auditing.
                body["razorpay"] = {"status": "no_call", "detail": "refused before payment"}
                self._ledger.append("refuse", body)

            return verdict

    # --- read surfaces the UI and tests use ----------------------------------

    def spent_under_root(self, root: str) -> int:
        with self._commit_lock:
            return self._spent.get(root, 0)

    @property
    def ledger(self) -> SqliteLedger:
        return self._ledger


def intent_ledger_body(intent: Intent, verdict: Verdict) -> dict:
    """What we write to the audit log for a decision. Enough to reconstruct and
    verify the decision; no signing keys, no card data."""
    return {
        "merchant_id": intent.merchant_id,
        "root": intent.root if intent.chain else None,
        "signer": intent.signer if intent.chain else None,
        "idempotency_key": intent.idempotency_key,
        "nonce": intent.nonce,
        "items": [item.to_body() for item in intent.items],
        "stated_total_paise": intent.total_paise,
        "verdict": {
            "allowed": verdict.allowed,
            "reason_code": verdict.reason_code.value,
            "explanation": verdict.explanation,
        },
    }


def _verdict_from_payload(payload: dict) -> Verdict:
    """Reconstruct a Verdict from a replayed idempotency payload. The replayed
    verdict is the original decision, so a retry sees exactly what the first
    caller saw."""
    from sieve.contracts.verdict import CheckStep

    steps = tuple(
        CheckStep(
            name=step["name"],
            passed=step["passed"],
            detail=step["detail"],
            evidence=step.get("evidence", {}),
            duration_us=step.get("duration_us", 0),
        )
        for step in payload.get("steps", [])
    )
    return Verdict(
        allowed=payload["allowed"],
        reason_code=ReasonCode(payload["reason_code"]),
        explanation=payload["explanation"],
        steps=steps,
        evidence=payload.get("evidence", {}),
    )
