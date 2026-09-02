"""Buyer-agent guardrails, tested without depending on the model.

A well-behaved agent proves nothing about the guardrails — it just proves the
model happened to cooperate. These tests drive the agent's tool layer directly,
as a jailbroken or malfunctioning model would, and assert the bounds hold anyway.

Nothing here needs an API key: the LLM is only involved in *choosing* which tool
to call, and every guardrail sits below that choice.
"""

from __future__ import annotations

from sieve.agents.buyer import BuyerAgent, Guardrails, build_session
from sieve.agents.llm import LLMClient, LLMUnavailable


def session(**kw):
    s = build_session(**kw)
    return s["agent"], s["world"]


def test_agent_cannot_call_a_tool_outside_its_surface():
    agent, _ = session()
    out = agent._dispatch("transfer_funds", {"to": "attacker", "amount": 999999})
    assert "error" in out
    assert "not available" in out["error"]


def test_agent_cannot_set_its_own_price():
    """Structural guardrail: propose_purchase takes a SKU and a quantity. There
    is no price parameter, so a compromised agent has no way to express a
    discount — the price charged comes from the merchant's catalog."""
    agent, world = session()
    out = agent._propose_purchase("TRAILMUG", 1)
    assert out["allowed"] is True
    # Charged the catalog price, not anything the agent could have chosen.
    assert out["charged"] == "₹129.00"
    assert world.catalog.price_paise("TRAILMUG") == 129_00


def test_gateway_refuses_an_over_budget_purchase_the_agent_proposes():
    """The rogue-agent case. The model is bypassed entirely: we call the tool
    directly with a purchase that exceeds the mandate, exactly as a jailbroken
    agent would. The gateway refuses regardless of what the agent 'decided'."""
    agent, _ = session(ceiling_paise=1000_00)
    out = agent._propose_purchase("TENT-2P", 2)  # 2 x 899 = 1798 > 1000 ceiling
    assert out["allowed"] is False
    assert out["reason"] == "budget_exhausted"


def test_gateway_refuses_a_category_outside_the_mandate():
    agent, _ = session(categories=frozenset({"outdoor"}))
    out = agent._propose_purchase("TRAILMUG", 1)  # kitchen
    assert out["allowed"] is False
    assert out["reason"] == "category_not_permitted"


def test_purchase_attempt_limit_is_enforced_in_code():
    """A model that loops cannot drain the budget through repetition. The cap is
    a rule in code, not a request in the prompt."""
    agent, _ = session(ceiling_paise=100000_00)
    agent.rails = Guardrails(max_purchase_attempts=2)
    assert agent._propose_purchase("MAP-IN", 1)["allowed"] is True
    assert agent._propose_purchase("MAP-IN", 1)["allowed"] is True
    blocked = agent._propose_purchase("MAP-IN", 1)
    assert blocked.get("refused") is True
    assert blocked["reason"] == "purchase_attempt_limit"


def test_cumulative_spend_is_tracked_across_proposals():
    """Two purchases that each fit but together do not: the second is refused by
    the gateway's cumulative ceiling, not by the agent's goodwill."""
    agent, _ = session(ceiling_paise=1000_00)
    first = agent._propose_purchase("TENT-2P", 1)   # 899 <= 1000
    second = agent._propose_purchase("TENT-2P", 1)  # 1798 > 1000
    assert first["allowed"] is True
    assert second["allowed"] is False
    assert second["reason"] == "budget_exhausted"


def test_unknown_sku_is_handled_without_crashing():
    agent, _ = session()
    out = agent._propose_purchase("NOT-A-SKU", 1)
    assert out["refused"] is True
    assert out["reason"] == "unknown_sku"


def test_malformed_quantity_is_rejected_not_crashed():
    agent, _ = session()
    out = agent._propose_purchase("TENT-2P", -3)
    assert out["refused"] is True
    assert out["reason"] == "malformed"


def test_agent_degrades_gracefully_without_a_model():
    """The gateway does not depend on the model being reachable. With no key
    configured, the run reports the failure instead of raising."""
    agent, _ = session()
    agent.client = LLMClient(api_key="")
    run = agent.run("buy me a tent")
    assert run.stopped_by == "llm_unavailable"
    assert run.purchases == []


def test_a_tool_that_raises_returns_an_error_instead_of_killing_the_loop():
    agent, _ = session()
    agent._get_product = lambda sku: (_ for _ in ()).throw(RuntimeError("boom"))
    out = agent._dispatch("get_product", {"sku": "TENT-2P"})
    assert "error" in out and "RuntimeError" in out["error"]
