"""Property-based fuzzing of the one invariant that must never break.

The hand-written corpus tests 16 attacks I thought of. This searches a space I
did not — thousands of randomly generated delegation chains, including ones that
widen authority at arbitrary hops, in arbitrary combinations — against a single
property:

    THE HUMAN ROOT IS THE CEILING.
    No matter what any intermediate hop claims, an ALLOW can never let an order
    exceed what the human actually granted at the first hop — not in amount, not
    in category, not in capability.

This is the invariant the whole delegation model exists to guarantee. Because
authority narrows monotonically, the leaf is a subset of the root, so any
authorised order must fit inside the root's grant. If Hypothesis can construct a
chain where a widening hop lets an order slip past the root's ceiling, that is a
real, exploitable vulnerability — and it would shrink the counterexample to the
minimal chain that triggers it.

It passing across thousands of examples is a far stronger claim than "16 attacks
contained": it is "no generated chain, widening or not, ever moved money outside
the human's grant."
"""

from __future__ import annotations

from dataclasses import replace

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sieve.contracts.mandate import Authority, LineItem, utc_now
from sieve.gateway.crypto import DOMAIN_DELEGATION, SigningKey
from sieve.suite.targets import build_sieve
from sieve.suite.world import World
from datetime import timedelta

CATS = ["outdoor", "kitchen", "books"]
CAPS = ["catalog:read", "cart:write", "order:create", "payment:create", "refund:create"]
# (sku, category, unit_price_paise) — the real catalog.
CATALOG = [
    ("TENT-2P", "outdoor", 899_00), ("BAG-0C", "outdoor", 649_00),
    ("STOVE-CAN", "outdoor", 349_00), ("FILTER-SQ", "outdoor", 249_00),
    ("TRAILMUG", "kitchen", 129_00), ("MAP-IN", "books", 79_00),
]

authority_spec = st.fixed_dictionaries({
    "amount": st.integers(min_value=0, max_value=20_000_00),
    "cats": st.lists(st.sampled_from(CATS), unique=True, max_size=3),
    "caps": st.lists(st.sampled_from(CAPS), unique=True, max_size=5),
    "hours": st.integers(min_value=-3, max_value=48),
})


def _authority(now, spec) -> Authority:
    return Authority(
        max_amount_paise=spec["amount"],
        categories=frozenset(spec["cats"]),
        capabilities=frozenset(spec["caps"]),
        expires_at=now + timedelta(hours=spec["hours"]),
    )


@settings(max_examples=1000, deadline=None, derandomize=True,
          suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(
    hop_specs=st.lists(authority_spec, min_size=1, max_size=4),
    item=st.sampled_from(CATALOG),
    qty=st.integers(min_value=1, max_value=8),
)
def test_no_allow_ever_exceeds_the_root_grant(hop_specs, item, qty):
    world = World()
    gateway = build_sieve(world)
    now = world.now

    # Build a chain human -> k1 -> k2 -> ... where hop i carries hop_specs[i].
    # Each hop is honestly signed by its issuer — the ONLY thing under test is
    # whether authority relationships between hops are enforced, so signatures
    # must be valid or the intent is refused for the wrong reason.
    keys = [world.human] + [SigningKey.generate() for _ in hop_specs]
    chain = []
    for i, spec in enumerate(hop_specs):
        auth = _authority(now, spec)
        unsigned = replace(
            world.issue(keys[i], keys[i + 1], auth), signature=b"")
        signed = replace(unsigned,
                         signature=keys[i].sign(DOMAIN_DELEGATION, unsigned.to_body()))
        chain.append(signed)

    sku, category, price = item
    line = LineItem(sku=sku, category=category, quantity=qty, unit_price_paise=price)
    leaf_key = keys[len(hop_specs)]
    intent = world.intent(leaf_key, tuple(chain), [line])

    verdict = gateway.submit(intent)

    if not verdict.allowed:
        return  # a refusal can never move money outside the grant

    # ALLOWED — so the order MUST fit inside the ROOT grant (hop 0), whatever the
    # intermediate hops claimed.
    root = _authority(now, hop_specs[0])
    order_total = qty * price

    assert order_total <= root.max_amount_paise, (
        f"ALLOW moved {order_total} past the root ceiling {root.max_amount_paise}")
    assert category in root.categories, (
        f"ALLOW bought category {category!r} outside the root grant {sorted(root.categories)}")
    assert {"order:create", "payment:create"} <= root.capabilities, (
        f"ALLOW spent without the root granting order+payment capability: "
        f"{sorted(root.capabilities)}")
    # And the root itself must still be live.
    assert root.expires_at > now, "ALLOW under an already-expired root grant"


@settings(max_examples=500, deadline=None, derandomize=True,
          suppress_health_check=[HealthCheck.too_slow])
@given(hop_specs=st.lists(authority_spec, min_size=2, max_size=4))
def test_any_widening_hop_is_refused(hop_specs):
    """A sharper property: if ANY hop widens a dimension relative to its parent,
    the chain must be refused. Directly fuzzes the narrowing check itself."""
    world = World()
    gateway = build_sieve(world)
    now = world.now

    keys = [world.human] + [SigningKey.generate() for _ in hop_specs]
    chain = []
    widens = False
    for i, spec in enumerate(hop_specs):
        auth = _authority(now, spec)
        if i > 0:
            parent = _authority(now, hop_specs[i - 1])
            if parent.narrowing_violations(auth):
                widens = True
        unsigned = replace(world.issue(keys[i], keys[i + 1], auth), signature=b"")
        chain.append(replace(unsigned,
                     signature=keys[i].sign(DOMAIN_DELEGATION, unsigned.to_body())))

    line = LineItem(sku="MAP-IN", category="books", quantity=1, unit_price_paise=79_00)
    intent = world.intent(keys[len(hop_specs)], tuple(chain), [line])
    verdict = gateway.submit(intent)

    if widens:
        assert not verdict.allowed, "a chain with a widening hop was ALLOWED"
