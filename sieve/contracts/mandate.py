"""The authorisation model: Authority, Delegation, DelegationChain, Intent.

The idea this project is built around is that real agentic commerce is not
`user -> merchant`. It is:

    human -> assistant -> sub-agent -> merchant

and the merchant is at the far end of a chain it did not build, cannot see the
middle of, and must not trust. Every competitor surveyed asks "does this agent
hold a valid mandate?". None asks "does this agent legitimately act for this
human, through an unbroken chain?"

The invariant that makes the chain safe is **monotonic narrowing**: authority
can only ever shrink as it is passed along. A sub-agent cannot grant its
sub-agent more than it holds itself. Attack B7 is precisely an attempt to
violate that.

Design notes worth stating, because both are places bugs like to live:

  - "Unrestricted" is not representable. `categories` and `capabilities` are
    always explicit frozensets; there is no None-means-everything case. You
    cannot accidentally construct unlimited authority.
  - Timestamps enter the signing body as integer epoch milliseconds. The
    canonical encoder rejects floats, and integers have exactly one encoding.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

# The complete capability vocabulary. A capability not in this set is refused
# at construction — an unknown capability must never be silently carried along a
# chain, because a future version of the gateway might come to honour it.
CAPABILITIES: frozenset[str] = frozenset(
    {
        "catalog:read",
        "cart:write",
        "order:create",
        "payment:create",
        "refund:create",
    }
)


class MandateError(ValueError):
    """A mandate object is structurally invalid and must not be constructed."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_epoch_ms(moment: datetime) -> int:
    if moment.tzinfo is None:
        raise MandateError("naive datetime — timestamps must be timezone-aware")
    return int(moment.timestamp() * 1000)


def new_nonce() -> str:
    return secrets.token_hex(16)


@dataclass(frozen=True, slots=True)
class Authority:
    """What a holder is permitted to do.

    Every field is a *ceiling*. Narrowing means every ceiling moves down or
    stays put; none may rise.
    """

    max_amount_paise: int
    categories: frozenset[str]
    capabilities: frozenset[str]
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.max_amount_paise < 0:
            raise MandateError("max_amount_paise must be non-negative")
        unknown = self.capabilities - CAPABILITIES
        if unknown:
            raise MandateError(f"unknown capabilities: {sorted(unknown)}")
        if self.expires_at.tzinfo is None:
            raise MandateError("expires_at must be timezone-aware")

    def narrowing_violations(self, child: "Authority") -> list[str]:
        """Ways in which `child` claims more authority than `self` grants.

        Empty list means `child` is a valid narrowing. Each violation is phrased
        for a human, because it is surfaced verbatim in the refusal reason and
        in the UI's live verification pipeline.
        """
        violations: list[str] = []

        if child.max_amount_paise > self.max_amount_paise:
            violations.append(
                f"amount ceiling widened: child allows {child.max_amount_paise} paise, "
                f"parent allows {self.max_amount_paise}"
            )

        gained_categories = child.categories - self.categories
        if gained_categories:
            violations.append(
                f"categories widened: child adds {sorted(gained_categories)} "
                f"not held by parent"
            )

        gained_capabilities = child.capabilities - self.capabilities
        if gained_capabilities:
            violations.append(
                f"capabilities widened: child adds {sorted(gained_capabilities)} "
                f"not held by parent"
            )

        if child.expires_at > self.expires_at:
            violations.append(
                f"expiry extended: child expires {child.expires_at.isoformat()}, "
                f"parent expires {self.expires_at.isoformat()}"
            )

        return violations

    def narrowed(
        self,
        *,
        max_amount_paise: int | None = None,
        categories: frozenset[str] | None = None,
        capabilities: frozenset[str] | None = None,
        expires_at: datetime | None = None,
    ) -> "Authority":
        """Derive a child authority that is guaranteed to be a valid narrowing.

        Every requested value is clamped against this authority's ceiling, so an
        honest issuer cannot accidentally produce a chain that fails
        verification. Omitted fields inherit the parent's value unchanged.

        This exists because of a real bug found while building the test suite.
        The obvious way to write "delegate for 24 hours" is
        `expires_at=utc_now() + timedelta(hours=24)` — but if the parent was
        itself issued microseconds earlier with a 24-hour window, the child now
        outlives it and the chain is correctly rejected as widened. The verifier
        was right; the *ergonomics* were the problem. Clamping here makes the
        safe thing the easy thing, and leaves the verifier free to stay strict.

        Note this cannot be used to widen: passing a larger amount than the
        parent holds silently clamps down to the parent's ceiling rather than
        raising, because callers routinely say "give it ₹500" without knowing
        what they themselves hold.
        """
        return Authority(
            max_amount_paise=min(
                self.max_amount_paise,
                self.max_amount_paise if max_amount_paise is None else max_amount_paise,
            ),
            categories=self.categories
            if categories is None
            else (categories & self.categories),
            capabilities=self.capabilities
            if capabilities is None
            else (capabilities & self.capabilities),
            expires_at=min(
                self.expires_at,
                self.expires_at if expires_at is None else expires_at,
            ),
        )

    def to_body(self) -> dict:
        """The signed representation. Ordering is irrelevant — the canonical
        encoder sorts — but the field set is part of what the signature binds."""
        return {
            "max_amount_paise": self.max_amount_paise,
            "categories": self.categories,
            "capabilities": self.capabilities,
            "expires_at_ms": to_epoch_ms(self.expires_at),
        }


@dataclass(frozen=True, slots=True)
class Delegation:
    """One signed hop: `issuer` grants `subject` the stated authority.

    The signature is made by `issuer` over `signing_payload("delegation", body)`.
    """

    issuer: str  # hex-encoded Ed25519 public key
    subject: str  # hex-encoded Ed25519 public key
    authority: Authority
    nonce: str
    issued_at: datetime
    signature: bytes

    def to_body(self) -> dict:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "authority": self.authority.to_body(),
            "nonce": self.nonce,
            "issued_at_ms": to_epoch_ms(self.issued_at),
        }


@dataclass(frozen=True, slots=True)
class LineItem:
    sku: str
    category: str
    quantity: int
    unit_price_paise: int

    def __post_init__(self) -> None:
        # Attack D14 lives here. A negative quantity would let a cart total be
        # driven down — or negative — while every individual price looks sane.
        if self.quantity <= 0:
            raise MandateError(f"quantity must be positive, got {self.quantity}")
        if self.unit_price_paise < 0:
            raise MandateError(
                f"unit_price_paise must be non-negative, got {self.unit_price_paise}"
            )

    @property
    def subtotal_paise(self) -> int:
        return self.quantity * self.unit_price_paise

    def to_body(self) -> dict:
        return {
            "sku": self.sku,
            "category": self.category,
            "quantity": self.quantity,
            "unit_price_paise": self.unit_price_paise,
        }


@dataclass(frozen=True, slots=True)
class Intent:
    """What the acting agent wants to do, right now, signed by that agent.

    `chain` is the delegation chain from the human's root key down to the agent
    signing this intent. `chain[-1].subject` must be the intent's signer — an
    agent may only act with authority delegated *to it*.

    `total_paise` is stated by the agent and independently recomputed by the
    gateway. A mismatch is a refusal, not a correction: if the two disagree, we
    do not know which one the human authorised.
    """

    chain: tuple[Delegation, ...]
    merchant_id: str
    items: tuple[LineItem, ...]
    total_paise: int
    nonce: str
    idempotency_key: str
    created_at: datetime
    signature: bytes
    currency: str = "INR"

    def __post_init__(self) -> None:
        if not self.chain:
            raise MandateError("intent must carry a non-empty delegation chain")
        if not self.items:
            raise MandateError("intent must contain at least one line item")
        if self.currency != "INR":
            raise MandateError(f"unsupported currency: {self.currency}")

    @property
    def signer(self) -> str:
        """The public key that must have signed this intent."""
        return self.chain[-1].subject

    @property
    def root(self) -> str:
        """The human's root public key at the head of the chain."""
        return self.chain[0].issuer

    def computed_total_paise(self) -> int:
        return sum(item.subtotal_paise for item in self.items)

    def categories(self) -> frozenset[str]:
        return frozenset(item.category for item in self.items)

    def to_body(self) -> dict:
        return {
            "chain": [link.to_body() for link in self.chain],
            "chain_signatures": [link.signature for link in self.chain],
            "merchant_id": self.merchant_id,
            "items": [item.to_body() for item in self.items],
            "total_paise": self.total_paise,
            "currency": self.currency,
            "nonce": self.nonce,
            "idempotency_key": self.idempotency_key,
            "created_at_ms": to_epoch_ms(self.created_at),
        }
