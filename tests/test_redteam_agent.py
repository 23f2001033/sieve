"""Red-team agent: sandboxing and harness correctness, without needing a model.

Two things must be true of a tool that attacks your own system: it must be unable
to reach anything real, and its harness must be capable of detecting the attacks
it claims to test. The second is not obvious — the agent's very first run
reported a successful nonce replay that turned out to be an artifact of a harness
that rebuilt the gateway between probes. These tests pin both properties.
"""

from __future__ import annotations

from sieve.agents.llm import LLMClient
from sieve.agents.redteam import RedTeamAgent, _catalog_brief


def test_probes_share_one_gateway_so_stateful_attacks_are_detectable():
    """The harness bug the agent found. If each probe got a fresh gateway, a
    replayed nonce would always 'succeed' because the target had never seen it —
    making replay untestable and producing a false finding."""
    agent = RedTeamAgent()
    spec = {"description": "baseline", "expectation": "allow",
            "hops": [{"max_amount_paise": 500_00, "categories": ["outdoor"]}],
            "sku": "FILTER-SQ", "quantity": 1}

    allowed_first, _ = agent._build_and_submit(spec)
    assert allowed_first is True

    # Same nonce, same gateway: the replay must now be caught.
    allowed_replay, reason = agent._build_and_submit({**spec, "reuse_nonce": True})
    assert allowed_replay is False
    assert reason == "nonce_replayed", f"expected replay detection, got {reason}"


def test_the_red_team_gateway_cannot_reach_a_payment_rail():
    """Defence-only by construction: the sandbox gateway has the null rail, so no
    probe can create a Razorpay order however it is shaped."""
    agent = RedTeamAgent()
    agent._build_and_submit({"description": "b", "expectation": "allow",
                             "hops": [{"max_amount_paise": 500_00}],
                             "sku": "MAP-IN", "quantity": 1})
    rail = agent._gateway._payments
    assert rail.configured is False
    assert type(rail).__name__ == "NullRail"


def test_widening_probe_is_refused():
    agent = RedTeamAgent()
    allowed, reason = agent._build_and_submit({
        "description": "widen the ceiling at hop 2", "expectation": "refuse",
        "hops": [{"max_amount_paise": 100_00}, {"max_amount_paise": 900_00}],
        "sku": "TENT-2P", "quantity": 1})
    assert allowed is False
    assert reason == "authority_widened"


def test_forged_signer_probe_is_refused():
    agent = RedTeamAgent()
    allowed, reason = agent._build_and_submit({
        "description": "sign with a key that holds no delegation",
        "expectation": "refuse",
        "hops": [{"max_amount_paise": 500_00, "categories": ["books"]}],
        "sku": "MAP-IN", "quantity": 1, "sign_with": "stranger"})
    assert allowed is False
    assert reason == "signature_invalid"


def test_broken_linkage_probe_is_refused():
    agent = RedTeamAgent()
    allowed, reason = agent._build_and_submit({
        "description": "last hop issued by an undelegated key",
        "expectation": "refuse",
        "hops": [{"max_amount_paise": 500_00}, {"max_amount_paise": 400_00}],
        "sku": "MAP-IN", "quantity": 1, "break_linkage": True})
    assert allowed is False
    assert reason == "chain_broken"


def test_a_malformed_spec_does_not_crash_the_harness():
    """The model produces arbitrary JSON. A bad spec must become a refused probe,
    never an exception that ends the run."""
    agent = RedTeamAgent()
    allowed, reason = agent._build_and_submit({"description": "junk", "expectation": "refuse",
                                               "hops": [], "sku": "NOPE", "quantity": 0})
    assert allowed is False


def test_needs_review_only_flags_allowed_probes_the_agent_expected_refused():
    from sieve.agents.redteam import Probe

    assert Probe("d", "refuse", True, "allowed", {}).needs_review is True
    assert Probe("d", "refuse", False, "x", {}).needs_review is False
    assert Probe("d", "allow", True, "allowed", {}).needs_review is False


def test_catalog_brief_lists_the_real_catalog():
    """The agent cannot attack what it cannot see — and the brief must not drift
    from what the gateway actually sells."""
    brief = _catalog_brief()
    for sku in ("TENT-2P", "TRAILMUG", "MAP-IN"):
        assert sku in brief
    assert "outdoor" in brief and "kitchen" in brief


def test_degrades_without_a_model():
    agent = RedTeamAgent(client=LLMClient(api_key=""))
    run = agent.run()
    assert run.stopped_by == "llm_unavailable"
    assert run.probes == []
