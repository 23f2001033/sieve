"""Attack family B — the delegation chain.

This is the family no surveyed competitor tests, because no competitor models a
chain at all — they check a single mandate. Each attack here corrupts one link
of a `human -> assistant -> tool` chain in a mechanistically distinct way: forge
a signature, splice a broken hand-off, widen authority at a hop, or bomb the
depth. The naive gateway inspects only the leaf mandate, so it misses every one
that lives above the leaf.
"""

from __future__ import annotations

from dataclasses import replace

from sieve.contracts.adapter import GatewayAdapter
from sieve.contracts.verdict import ReasonCode, Verdict
from sieve.gateway.crypto import DOMAIN_DELEGATION, SigningKey
from sieve.suite.corpus import Attack
from sieve.suite.world import World


class B5_ForgedIntermediateSignature(Attack):
    attack_id = "B5"
    family = "Delegation chain"
    name = "Forged issuer signature on an intermediate link"
    expected_reasons = frozenset({ReasonCode.SIGNATURE_INVALID})

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        # hop 0 (human -> assistant) is signed by a stranger pretending to be the
        # human; hop 1 (assistant -> tool) is validly signed by the assistant.
        # A gateway that checks only the leaf sees a valid leaf and accepts. The
        # forged root goes unnoticed unless every link is verified.
        hop0 = world.issue(world.human, world.assistant, world.authority(amount_paise=5000_00))
        forged0 = replace(
            hop0,
            signature=world.stranger.sign(DOMAIN_DELEGATION, replace(hop0, signature=b"").to_body()),
        )
        hop1 = world.issue(world.assistant, world.tool, world.authority(amount_paise=2000_00, hours=12))
        intent = world.intent(world.tool, (forged0, hop1), [world.item("TENT-2P")])
        return adapter.submit(intent)


class B6_ChainLinkSplice(Attack):
    attack_id = "B6"
    family = "Delegation chain"
    name = "Chain link splice — hop issued by an undelegated key"
    expected_reasons = frozenset({ReasonCode.CHAIN_BROKEN})

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        # hop 1 is issued by the stranger, whom hop 0 never delegated to. The
        # signatures are individually valid; the CHAIN is spliced. Only a gateway
        # that checks issuer-to-subject linkage catches this.
        hop0 = world.issue(world.human, world.assistant, world.authority())
        spliced = world.issue(world.stranger, world.tool, world.authority(amount_paise=2000_00, hours=12))
        intent = world.intent(world.tool, (hop0, spliced), [world.item("TENT-2P")])
        return adapter.submit(intent)


class B7_AuthorityWideningAtAHop(Attack):
    attack_id = "B7"
    family = "Delegation chain"
    name = "Authority widening at a hop"
    expected_reasons = frozenset({ReasonCode.AUTHORITY_WIDENED})

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        # The headline attack. A sub-agent grants itself a HIGHER ceiling than it
        # was granted — ₹500 in, ₹5,000 out. Authority may only narrow along a
        # chain; this widens it. Every link is validly signed, so only the
        # narrowing invariant catches it.
        hop0 = world.issue(world.human, world.assistant, world.authority(amount_paise=500_00))
        widened = world.issue(world.assistant, world.tool, world.authority(amount_paise=5000_00, hours=12))
        intent = world.intent(world.tool, (hop0, widened), [world.item("TENT-2P")])
        return adapter.submit(intent)


class B8_DelegationDepthBomb(Attack):
    attack_id = "B8"
    family = "Delegation chain"
    name = "Delegation depth bomb (resource exhaustion)"
    expected_reasons = frozenset({ReasonCode.MALFORMED})

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        # A chain far deeper than any real delegation, submitted to make the
        # gateway verify a long series of signatures. SIEVE bounds depth BEFORE
        # any cryptography runs, so the work is rejected cheaply — the check
        # order is itself the defence.
        links = []
        current = world.human
        for _ in range(20):
            nxt = SigningKey.generate()
            links.append(world.issue(current, nxt, world.authority()))
            current = nxt
        # `current` holds the leaf key; sign the intent with it.
        intent = world.intent(current, tuple(links), [world.item("MAP-IN")])
        return adapter.submit(intent)


DELEGATION_ATTACKS = [
    B5_ForgedIntermediateSignature(),
    B6_ChainLinkSplice(),
    B7_AuthorityWideningAtAHop(),
    B8_DelegationDepthBomb(),
]
