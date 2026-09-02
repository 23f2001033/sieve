"""The benign corpus — legitimate transactions that MUST be allowed.

This is the denominator of the honesty metric. Containment means nothing without
it: a gateway that refuses everything "contains" every attack and is useless.
The false-refusal rate — legitimate transactions wrongly blocked — is reported
next to containment, always, so the two numbers constrain each other.

One template here is deliberately a known false refusal: FavourablePriceDrop. If
the catalog price drops between quote and checkout, SIEVE refuses, because the
buyer authorised a transaction on specific terms and the terms changed. That is
a conservative, defensible, and *reversible* policy choice — and it is the
dominant source of the reported false-refusal rate. Reporting it rather than
tuning it away is the point: the honest number is the credible one.
"""

from __future__ import annotations

import random
from dataclasses import replace

from sieve.contracts.adapter import GatewayAdapter
from sieve.contracts.mandate import LineItem, new_nonce
from sieve.contracts.verdict import Verdict
from sieve.gateway.crypto import DOMAIN_DELEGATION, DOMAIN_INTENT, SigningKey
from sieve.suite.corpus import BenignCase, BenignResult
from sieve.suite.world import World

OUTDOOR_SKUS = ["TENT-2P", "BAG-0C", "STOVE-CAN", "FILTER-SQ"]


class NormalPurchase(BenignCase):
    def __init__(self, n: int, sku: str) -> None:
        self.case_id = f"BN-normal-{n}"
        self.name = f"Single-item purchase ({sku})"
        self._sku = sku

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        chain = world.default_chain()
        return adapter.submit(world.intent(world.tool, chain, [world.item(self._sku)]))


class MultiItem(BenignCase):
    def __init__(self, n: int, skus: list[str]) -> None:
        self.case_id = f"BN-multi-{n}"
        self.name = "Multi-item cart"
        self._skus = skus

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        chain = world.default_chain()
        items = [world.item(s) for s in self._skus]
        return adapter.submit(world.intent(world.tool, chain, items))


class BudgetBoundary(BenignCase):
    """An order totalling EXACTLY the authority ceiling. The classic off-by-one:
    <= must pass, only > may fail."""

    def __init__(self, n: int, sku: str) -> None:
        self.case_id = f"BN-boundary-{n}"
        self.name = f"Order exactly at the budget ceiling ({sku})"
        self._sku = sku

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        price = world.catalog.price_paise(self._sku)
        chain = (world.issue(world.human, world.assistant, world.authority(amount_paise=price)),)
        return adapter.submit(world.intent(world.assistant, chain, [world.item(self._sku)]))


class ThreeHopDelegation(BenignCase):
    """human -> assistant -> tool -> buyer-2, each hop honestly narrowing. The
    realistic shape of a real agent stack, and it must be allowed."""

    def __init__(self, n: int) -> None:
        self.case_id = f"BN-3hop-{n}"
        self.name = "Legitimate three-hop delegation"

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        buyer2 = SigningKey.generate()
        a0 = world.authority(amount_paise=5000_00, hours=24)
        a1 = a0.narrowed(max_amount_paise=2000_00)
        a2 = a1.narrowed(max_amount_paise=1500_00, categories=frozenset({"outdoor"}))
        d0 = world.issue(world.human, world.assistant, a0)
        d1 = world.issue(world.assistant, world.tool, a1)
        # third hop signed by the tool, delegating to buyer-2
        unsigned = replace(
            world.issue(world.tool, buyer2, a2), signature=b"",
        )
        d2 = replace(unsigned, signature=world.tool.sign(DOMAIN_DELEGATION, unsigned.to_body()))
        return adapter.submit(world.intent(buyer2, (d0, d1, d2), [world.item("TENT-2P")]))


class HonestRetry(BenignCase):
    """A client submits, the response is lost, it retries with the SAME
    idempotency key. The retry must return the original result — NOT a refusal.
    Refusing an honest retry is the false refusal we most want to avoid."""

    def __init__(self, n: int) -> None:
        self.case_id = f"BN-retry-{n}"
        self.name = "Legitimate retry after a timeout"

    def run(self, adapter: GatewayAdapter, world: World) -> BenignResult:
        chain = world.default_chain()
        key, nonce = new_nonce(), new_nonce()
        intent = world.intent(world.tool, chain, [world.item("FILTER-SQ")],
                              idempotency_key=key, nonce=nonce)
        adapter.submit(intent)            # first attempt (response "lost")
        second = adapter.submit(intent)   # the retry
        return BenignResult(case_id=self.case_id, name=self.name,
                            allowed=second.allowed, actual_reason=second.reason_code.value)


class FavourablePriceDrop(BenignCase):
    """The catalog price DROPS between quote and checkout. SIEVE refuses — the
    buyer authorised specific terms. A known, deliberate false refusal, and the
    dominant source of the reported rate. Documented, not hidden."""

    def __init__(self, n: int) -> None:
        self.case_id = f"BN-drop-{n}"
        self.name = "Price dropped in the buyer's favour (known false refusal)"

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        chain = world.default_chain()
        intent = world.intent(world.tool, chain, [world.item("TENT-2P")])
        world.catalog.set_price("TENT-2P", 799_00)  # dropped from 899 after the quote
        return adapter.submit(intent)


def benign_corpus(n: int = 200, seed: int = 42) -> list[BenignCase]:
    """A reproducible mix of legitimate transactions.

    Proportions reflect realistic traffic: favourable price drops are rare
    (prices seldom move between quote and checkout), so FavourablePriceDrop is a
    small minority. The false-refusal rate falls out of the mix rather than being
    tuned to a target — change the seed and the number moves within its interval.
    """
    rng = random.Random(seed)
    cases: list[BenignCase] = []
    for i in range(n):
        roll = rng.random()
        if roll < 0.02:                    # ~2% — the known false refusal
            cases.append(FavourablePriceDrop(i))
        elif roll < 0.22:
            cases.append(MultiItem(i, rng.sample(OUTDOOR_SKUS, k=2)))
        elif roll < 0.40:
            cases.append(BudgetBoundary(i, rng.choice(OUTDOOR_SKUS)))
        elif roll < 0.58:
            cases.append(ThreeHopDelegation(i))
        elif roll < 0.74:
            cases.append(HonestRetry(i))
        else:
            cases.append(NormalPurchase(i, rng.choice(OUTDOOR_SKUS)))
    return cases
