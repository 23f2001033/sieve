"""The payment rail is reached only after ALLOW.

This is the test behind the phrase "bounded and gated". It is easy to write a
gateway that decides correctly and then calls the payment API anyway on some
error path; the only way to know that isn't happening is to count the calls.

A spy rail records every invocation, so "a refused intent never reaches the
payment API" becomes a measured fact rather than a design intention.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from sieve.gateway.razorpay import NullRail, OrderResult, RazorpayTestMode
from sieve.suite.attacks import ALL_ATTACKS
from sieve.suite.targets import build_sieve
from sieve.suite.world import World


class SpyRail:
    """Counts calls. The whole point is that the count stays zero on refusals."""

    configured = True
    is_test_mode = True

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def create_order(self, *, amount_paise: int, receipt: str, notes=None) -> OrderResult:
        self.calls.append({"amount_paise": amount_paise, "receipt": receipt})
        return OrderResult("created", f"order_spy_{len(self.calls)}", amount_paise, "spy")


def gateway_with(spy: SpyRail, world: World):
    gw = build_sieve(world)
    gw._payments = spy
    return gw


def test_an_allowed_purchase_reaches_the_rail_exactly_once():
    world = World()
    spy = SpyRail()
    gw = gateway_with(spy, world)
    verdict = gw.submit(world.intent(world.tool, world.default_chain(), [world.item("TENT-2P")]))

    assert verdict.allowed
    assert len(spy.calls) == 1
    assert spy.calls[0]["amount_paise"] == 899_00
    assert verdict.evidence["razorpay"]["status"] == "created"


# Three attacks open with a LEGITIMATE submission and only then turn malicious:
#   A1  buys once honestly, then replays that intent's nonce
#   C9  buys once within budget, then splits a second order under the cap
#   C11 races 25 copies of one valid purchase
# For those, exactly one charge is the correct outcome — the setup purchase was
# genuinely authorised. Every other attack must produce no payment call at all.
LEGITIMATE_SETUP_CHARGE = {"A1", "C9", "C11"}


def test_no_attack_causes_an_unauthorised_payment():
    """The headline safety property: no attack ever produces a payment beyond the
    legitimately authorised one, if any. The malicious submission never charges."""
    offenders = []
    for attack in ALL_ATTACKS:
        world = World()
        spy = SpyRail()
        gw = gateway_with(spy, world)
        attack.run(gw, world)
        limit = 1 if attack.attack_id in LEGITIMATE_SETUP_CHARGE else 0
        if len(spy.calls) > limit:
            offenders.append((attack.attack_id, len(spy.calls), limit))
    assert not offenders, f"attacks that over-charged (id, calls, allowed): {offenders}"


def test_the_malicious_half_of_a_multi_step_attack_never_charges():
    """A1 and C9 charge once for their honest setup purchase and never again —
    pinning the boundary the test above only bounds."""
    for attack_id in ("A1", "C9"):
        attack = next(a for a in ALL_ATTACKS if a.attack_id == attack_id)
        world = World()
        spy = SpyRail()
        gw = gateway_with(spy, world)
        result = attack.run(gw, world)
        assert result.contained, f"{attack_id} should be contained"
        assert len(spy.calls) == 1, (
            f"{attack_id}: expected only the legitimate setup charge, "
            f"got {len(spy.calls)}"
        )


def test_a_refusal_records_that_no_call_was_made():
    """Absence of a payment call is itself audited — the ledger says so."""
    world = World()
    spy = SpyRail()
    gw = gateway_with(spy, world)
    # Authority widening: refused before any payment.
    chain = (
        world.issue(world.human, world.assistant, world.authority(amount_paise=500_00)),
        world.issue(world.assistant, world.tool, world.authority(amount_paise=5000_00, hours=12)),
    )
    verdict = gw.submit(world.intent(world.tool, chain, [world.item("TENT-2P")]))

    assert not verdict.allowed
    assert spy.calls == []
    entry = gw.ledger.entries()[-1]
    assert entry.kind == "refuse"
    assert entry.body["razorpay"]["status"] == "no_call"


def test_null_rail_is_recorded_not_silently_skipped():
    rail = NullRail()
    out = rail.create_order(amount_paise=1000, receipt="r")
    assert out.status == "stub"
    assert out.order_id is None


def test_a_live_key_is_refused_outright():
    """An autonomous agent creating orders must never be pointed at a production
    key by accident. The prefix check is a hard stop, not a warning."""
    rail = RazorpayTestMode(key_id="rzp_live_pretend", key_secret="secret")
    out = rail.create_order(amount_paise=1000, receipt="r")
    assert out.status == "error"
    assert "non-test key" in out.detail


def test_missing_credentials_degrade_to_a_recorded_stub():
    rail = RazorpayTestMode(key_id="", key_secret="")
    assert not rail.configured
    out = rail.create_order(amount_paise=1000, receipt="r")
    assert out.status == "stub"
    assert "no Razorpay credentials" in out.detail
