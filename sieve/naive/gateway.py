"""The naive baseline gateway — the design most agentic-commerce entries ship.

This is NOT a strawman built to lose, and it is deliberately NOT naive about
cryptography. It verifies signatures correctly, with the same canonical scheme
SIEVE uses. Its naivety is in the *authorization logic* — which is exactly where
the surveyed competitors are naive. They pull in a crypto library, verify a
mandate signature, check `amount <= cap`, and call that "bounded and gated."

Making the baseline crypto-correct matters for fairness: a baseline that also
rejected honest customers (because it couldn't verify the signatures at all)
would "contain" every attack by refusing everything, and prove nothing. This one
lets legitimate traffic through, which is what makes the attacks it *also* lets
through meaningful.

Its weaknesses are the realistic ones, and each isolates one SIEVE contribution:

  - Verifies only the LEAF mandate, not the delegation chain's narrowing
    (attack B7: a sub-agent that widened its own authority passes).
  - Does not verify the intent's own signature or bind it to the leaf agent
    (attack A3: an intent the delegated agent never authored passes).
  - Trusts the intent's stated total instead of recomputing from the catalog
    (attacks A2/D14/D15: tampered total, TOCTOU price).
  - Per-order cap only, no cumulative budget (attack C9: split orders).
  - Non-atomic check-then-add nonce (attack C11: concurrent replay).

It genuinely contains the basic attacks — expired mandate, wrong merchant,
single-threaded replay — which is what makes the differential credible rather
than a shutout.
"""

from __future__ import annotations

import threading

from sieve.contracts.mandate import Intent
from sieve.contracts.verdict import ReasonCode, StepRecorder, Verdict
from sieve.gateway.crypto import DOMAIN_DELEGATION, verify_signature
from sieve.gateway.inventory import Northlight
from sieve.gateway.policy import Clock


class NaiveGateway:
    name = "Naive (amount cap + confirm)"

    def __init__(
        self,
        *,
        catalog: Northlight,
        clock: Clock,
        merchant_id: str,
        per_order_cap_paise: int = 2000_00,
    ) -> None:
        self._catalog = catalog
        self._clock = clock
        self._merchant_id = merchant_id
        self._cap = per_order_cap_paise
        self._used_nonces: set[str] = set()
        self._lock = threading.Lock()

    def submit(self, intent: Intent) -> Verdict:
        rec = StepRecorder()
        now = self._clock.now()

        if intent.merchant_id != self._merchant_id:
            rec.record("merchant_match", False, "different merchant")
            return rec.refuse(ReasonCode.MERCHANT_MISMATCH,
                              "Intent is for a different merchant.")
        rec.record("merchant_match", True, "addressed to this merchant")

        leaf = intent.chain[-1]

        # Leaf mandate expiry — checked.
        if leaf.authority.expires_at <= now:
            rec.record("mandate_unexpired", False, "leaf mandate expired")
            return rec.refuse(ReasonCode.LINK_EXPIRED, "Mandate has expired.")
        rec.record("mandate_unexpired", True, "leaf mandate is live")

        # Leaf mandate signature — verified correctly. But ONLY the leaf: the
        # naive gateway never walks the chain, so it never checks that the leaf's
        # issuer was itself validly delegated to, nor that authority narrowed.
        if not verify_signature(
            leaf.issuer, DOMAIN_DELEGATION, leaf.to_body(), leaf.signature
        ):
            rec.record("leaf_signature", False, "leaf mandate signature invalid")
            return rec.refuse(ReasonCode.SIGNATURE_INVALID, "Invalid mandate signature.")
        rec.record("leaf_signature", True, "leaf mandate signature verifies")

        # NOTE: the intent's OWN signature is never checked. Holding a mandate is
        # treated as authority to submit any intent under it — attack A3.

        # Nonce — non-atomic check now, add later. The window between is attack
        # C11's opening under real concurrency.
        with self._lock:
            already = intent.nonce in self._used_nonces
        if already:
            rec.record("nonce_unused", False, "nonce already seen")
            return rec.refuse(ReasonCode.NONCE_REPLAYED, "Replay detected.")
        rec.record("nonce_unused", True, "nonce not seen before")

        # Amount — against the LEAF mandate and the STATED total. No chain
        # narrowing, no catalog recomputation, no cumulative budget.
        if intent.total_paise > leaf.authority.max_amount_paise:
            rec.record("within_mandate", False, "over leaf mandate amount")
            return rec.refuse(ReasonCode.AMOUNT_EXCEEDS_AUTHORITY,
                              "Order exceeds the mandate amount.")
        if intent.total_paise > self._cap:
            rec.record("within_cap", False, "over per-order cap")
            return rec.refuse(ReasonCode.BUDGET_EXHAUSTED, "Order exceeds the cap.")
        rec.record("within_mandate", True, "within the leaf mandate amount")
        rec.record("within_cap", True, "within the per-order cap")

        with self._lock:
            self._used_nonces.add(intent.nonce)

        return rec.allow(
            f"Authorised ₹{intent.total_paise / 100:.2f} (naive checks passed)."
        )
