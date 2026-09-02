"""The shared world an attack and a gateway both agree on.

An attack needs valid keys to mutate, a registered human root, and builders for
honest delegations and intents — so that the ONLY thing wrong with an attack's
submission is the specific thing that attack is testing. If a "budget evasion"
attack also had a broken signature, it would be refused for the wrong reason and
prove nothing. The World hands every attack a clean, valid baseline to corrupt.

Both gateway targets (SIEVE and the naive baseline) are constructed from the
same World, so they share the merchant id, the catalog, and the set of trusted
root keys. That is what makes the differential fair: identical inputs, identical
trust assumptions, only the gateway differs.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

from sieve.contracts.mandate import (
    Authority,
    Delegation,
    Intent,
    LineItem,
    new_nonce,
    utc_now,
)
from sieve.gateway.crypto import DOMAIN_DELEGATION, DOMAIN_INTENT, SigningKey
from sieve.gateway.inventory import FixedClock, Northlight

MERCHANT_ID = "northlight-outdoors"

ALL_CATEGORIES = frozenset({"outdoor", "kitchen", "books"})
ALL_CAPABILITIES = frozenset(
    {"catalog:read", "cart:write", "order:create", "payment:create"}
)


class World:
    """Fixed keys and a fixed clock, so a whole corpus run is deterministic and
    reproducible from a seed. The human key is the sole trusted root."""

    def __init__(self, *, now: datetime | None = None) -> None:
        self.now = now or utc_now()
        self.clock = FixedClock(self.now)
        self.human = SigningKey.generate()
        self.assistant = SigningKey.generate()
        self.tool = SigningKey.generate()
        self.stranger = SigningKey.generate()
        self.catalog = Northlight()
        self.trusted_roots = frozenset({self.human.public_hex})

    # --- builders: honest by default, corrupted by the attack ----------------

    def authority(
        self,
        *,
        amount_paise: int = 5000_00,
        categories: frozenset[str] = ALL_CATEGORIES,
        capabilities: frozenset[str] = ALL_CAPABILITIES,
        hours: int = 24,
    ) -> Authority:
        return Authority(
            max_amount_paise=amount_paise,
            categories=categories,
            capabilities=capabilities,
            expires_at=self.now + timedelta(hours=hours),
        )

    def issue(
        self, issuer: SigningKey, subject: SigningKey, authority: Authority
    ) -> Delegation:
        unsigned = Delegation(
            issuer=issuer.public_hex,
            subject=subject.public_hex,
            authority=authority,
            nonce=new_nonce(),
            issued_at=self.now,
            signature=b"",
        )
        return replace(
            unsigned, signature=issuer.sign(DOMAIN_DELEGATION, unsigned.to_body())
        )

    def default_chain(self) -> tuple[Delegation, ...]:
        """human -> assistant -> tool, honestly narrowing. The baseline most
        attacks corrupt one link of."""
        return (
            self.issue(self.human, self.assistant, self.authority(amount_paise=5000_00)),
            self.issue(
                self.assistant,
                self.tool,
                self.authority(amount_paise=2000_00, hours=12),
            ),
        )

    def item(self, sku: str) -> LineItem:
        product = self.catalog.product(sku)
        assert product is not None, f"unknown sku {sku}"
        return LineItem(
            sku=product.sku,
            category=product.category,
            quantity=1,
            unit_price_paise=product.price_paise,
        )

    def intent(
        self,
        signer: SigningKey,
        chain: tuple[Delegation, ...],
        items: list[LineItem],
        *,
        total_paise: int | None = None,
        merchant_id: str = MERCHANT_ID,
        nonce: str | None = None,
        idempotency_key: str | None = None,
        sign: bool = True,
    ) -> Intent:
        total = (
            sum(i.quantity * i.unit_price_paise for i in items)
            if total_paise is None
            else total_paise
        )
        unsigned = Intent(
            chain=tuple(chain),
            merchant_id=merchant_id,
            items=tuple(items),
            total_paise=total,
            nonce=nonce or new_nonce(),
            idempotency_key=idempotency_key or new_nonce(),
            created_at=self.now,
            signature=b"",
        )
        if not sign:
            return unsigned
        return replace(
            unsigned, signature=signer.sign(DOMAIN_INTENT, unsigned.to_body())
        )

    def sign_intent(self, signer: SigningKey, intent: Intent) -> Intent:
        return replace(intent, signature=signer.sign(DOMAIN_INTENT, intent.to_body()))
