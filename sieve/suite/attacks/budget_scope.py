"""Attack family C — budget, scope, and concurrency.

Four distinct ways to spend outside the authority the human actually granted:
exceed the budget in aggregate while staying under it per order, buy in a
forbidden category, race a duplicate through, or act without the capability.
Each targets a different check, and the naive gateway — which knows only a
per-order cap — misses all four.
"""

from __future__ import annotations

import threading

from sieve.contracts.adapter import GatewayAdapter
from sieve.contracts.mandate import LineItem, new_nonce
from sieve.contracts.verdict import ReasonCode, Verdict
from sieve.suite.corpus import Attack, AttackResult
from sieve.suite.world import World

ALL_CAPS = frozenset({"catalog:read", "cart:write", "order:create", "payment:create"})


class C9_AggregateBudgetEvasion(Attack):
    attack_id = "C9"
    family = "Budget / scope / concurrency"
    name = "Aggregate budget evasion — split under the cap"
    expected_reasons = frozenset({ReasonCode.BUDGET_EXHAUSTED})

    def run(self, adapter: GatewayAdapter, world: World) -> AttackResult:
        # A ₹500 authority, spent as two ₹349 orders. Each is under the ceiling on
        # its own; their sum is not. A per-order check passes both. Only a
        # cumulative ceiling catches the second — which is the one judged.
        chain = (world.issue(world.human, world.assistant, world.authority(amount_paise=500_00)),)
        stove = LineItem(sku="STOVE-CAN", category="outdoor", quantity=1, unit_price_paise=349_00)

        first = adapter.submit(world.intent(world.assistant, chain, [stove]))
        second = adapter.submit(world.intent(world.assistant, chain, [stove]))
        return self._result(
            second,
            detail=f"first ₹349 {'allowed' if first.allowed else first.reason_code.value}; "
                   f"second ₹349 {'allowed' if second.allowed else second.reason_code.value}",
        )


class C10_CategoryScopeCreep(Attack):
    attack_id = "C10"
    family = "Budget / scope / concurrency"
    name = "Category scope creep"
    expected_reasons = frozenset({ReasonCode.CATEGORY_NOT_PERMITTED})

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        # Authority permits only 'outdoor'; the agent buys a 'kitchen' item.
        chain = (world.issue(world.human, world.assistant,
                             world.authority(categories=frozenset({"outdoor"}))),)
        mug = LineItem(sku="TRAILMUG", category="kitchen", quantity=1, unit_price_paise=129_00)
        return adapter.submit(world.intent(world.assistant, chain, [mug]))


class C11_ConcurrentDoubleSpend(Attack):
    attack_id = "C11"
    family = "Budget / scope / concurrency"
    name = "Concurrent double-spend (same key, raced)"
    expected_reasons = frozenset()  # judged by charge count, not a reason code

    def run(self, adapter: GatewayAdapter, world: World) -> AttackResult:
        # 25 threads submit the IDENTICAL intent at once. Contained means exactly
        # one fresh charge; the rest must be idempotent replays. This is a real
        # race released by a barrier, not a simulated one.
        chain = world.default_chain()
        intent = world.intent(world.tool, chain, [world.item("FILTER-SQ")],
                              idempotency_key=new_nonce(), nonce=new_nonce())

        n = 25
        barrier = threading.Barrier(n)
        fresh = [0]
        lock = threading.Lock()

        def worker():
            barrier.wait()
            v = adapter.submit(intent)
            # A fresh charge is an ALLOW that was NOT a replay. The naive gateway
            # has no replay concept, so each of its allows counts as fresh.
            if v.allowed and not v.evidence.get("replayed"):
                with lock:
                    fresh[0] += 1

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        charges = fresh[0]
        contained = charges == 1
        return AttackResult(
            attack_id=self.attack_id, family=self.family, name=self.name,
            contained=contained, reason_expected=contained,
            actual_reason="one_charge" if contained else f"{charges}_charges",
            detail=f"{charges} fresh charge(s) across {n} concurrent submissions",
        )


class C12_MissingCapability(Attack):
    attack_id = "C12"
    family = "Budget / scope / concurrency"
    name = "Acting without the payment capability"
    expected_reasons = frozenset({ReasonCode.CAPABILITY_MISSING})

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        # The authority was granted 'catalog:read' and 'order:create' but NOT
        # 'payment:create'. The agent tries to pay anyway.
        chain = (world.issue(
            world.human, world.assistant,
            world.authority(capabilities=frozenset({"catalog:read", "cart:write", "order:create"})),
        ),)
        return adapter.submit(world.intent(world.assistant, chain, [world.item("TENT-2P")]))


BUDGET_SCOPE_ATTACKS = [
    C9_AggregateBudgetEvasion(),
    C10_CategoryScopeCreep(),
    C11_ConcurrentDoubleSpend(),
    C12_MissingCapability(),
]
