"""Attack family A — authorization integrity.

Four ways to make a gateway act on a request the human never validly authorised:
replay a used one, tamper with a signed one, exploit serialisation ambiguity, or
use one that has expired or was minted for someone else. These are the most
fundamental attacks; a gateway that fails them fails everything downstream.
"""

from __future__ import annotations

from dataclasses import replace

from sieve.contracts.adapter import GatewayAdapter
from sieve.contracts.mandate import new_nonce
from sieve.contracts.verdict import ReasonCode, Verdict
from sieve.gateway.crypto import DOMAIN_INTENT
from sieve.suite.corpus import Attack, AttackResult
from sieve.suite.world import World


class A1_NonceReplay(Attack):
    attack_id = "A1"
    family = "Authorization integrity"
    name = "Nonce replay of a consumed intent"
    expected_reasons = frozenset({ReasonCode.NONCE_REPLAYED})

    def run(self, adapter: GatewayAdapter, world: World) -> AttackResult:
        # A replay attack is inherently two submissions: the first is legitimate
        # and should succeed; the SECOND — the attack — reuses the same nonce and
        # must be refused. Containment is judged on the second.
        chain = world.default_chain()
        shared_nonce = new_nonce()
        first = world.intent(world.tool, chain, [world.item("FILTER-SQ")], nonce=shared_nonce)
        adapter.submit(first)  # legitimate; may charge

        replay = world.intent(
            world.tool, chain, [world.item("FILTER-SQ")], nonce=shared_nonce
        )
        verdict = adapter.submit(replay)
        return self._result(verdict, detail="second submission reused the first's nonce")


class A2_AmountTamperedAfterSigning(Attack):
    attack_id = "A2"
    family = "Authorization integrity"
    name = "Line-item price lowered after the intent was signed"
    expected_reasons = frozenset(
        {ReasonCode.SIGNATURE_INVALID, ReasonCode.PRICE_CHANGED, ReasonCode.TOTAL_MISMATCH}
    )

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        # Sign an honest intent, then mutate a price without re-signing. The
        # signature no longer covers the bytes, and even a gateway that ignored
        # the signature would catch the price against the catalog.
        chain = world.default_chain()
        honest = world.intent(world.tool, chain, [world.item("TENT-2P")])
        tampered_item = replace(honest.items[0], unit_price_paise=1_00)
        tampered = replace(honest, items=(tampered_item,), total_paise=1_00)
        # deliberately NOT re-signed
        return adapter.submit(tampered)


class A3_IntentSignedByNonDelegatedKey(Attack):
    attack_id = "A3"
    family = "Authorization integrity"
    name = "Intent presented with a valid chain but signed by a non-delegated key"
    expected_reasons = frozenset({ReasonCode.SIGNATURE_INVALID})

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        # The attacker has obtained a legitimate delegation chain (human -> ...
        # -> tool) — say by eavesdropping — but does NOT hold the leaf key. They
        # compose their own intent and sign it with THEIR key. Holding a chain is
        # not the same as being the agent the chain was delegated to.
        #
        # SIEVE binds the intent signature to the chain leaf, so this is refused.
        # The naive gateway never verifies the intent's own signature at all — it
        # checks the delegation signature and the amount and nothing else — so it
        # accepts an intent the delegated agent never authored. That gap is the
        # differential.
        chain = world.default_chain()  # legitimately delegates to world.tool
        intent = world.intent(
            world.stranger,  # signs with the stranger's key, not the leaf (tool)
            chain,
            [world.item("MAP-IN")],
        )
        return adapter.submit(intent)


class A4_ExpiredMandate(Attack):
    attack_id = "A4"
    family = "Authorization integrity"
    name = "Intent presented on an expired delegation"
    expected_reasons = frozenset({ReasonCode.LINK_EXPIRED})

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        # A chain whose leaf mandate lapsed an hour ago.
        expired_leaf_auth = world.authority(amount_paise=2000_00, hours=-1)
        chain = (
            world.issue(world.human, world.assistant, world.authority(amount_paise=5000_00)),
            world.issue(world.assistant, world.tool, expired_leaf_auth),
        )
        intent = world.intent(world.tool, chain, [world.item("TENT-2P")])
        return adapter.submit(intent)


AUTHORIZATION_ATTACKS = [
    A1_NonceReplay(),
    A2_AmountTamperedAfterSigning(),
    A3_IntentSignedByNonDelegatedKey(),
    A4_ExpiredMandate(),
]
