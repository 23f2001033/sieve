"""Delegation-chain verification: the project's novel core.

These tests are written as *attacks*, not as happy-path coverage. Each one is a
thing a hostile agent would actually try, and the assertion is that the chain
verifier names the right refusal reason — not merely that it said no. A verifier
that refuses everything for the wrong reason is indistinguishable from a broken
one, and would sail through a test suite that only asserted `allowed is False`.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from sieve.contracts.mandate import (
    Authority,
    Delegation,
    new_nonce,
    utc_now,
)
from sieve.contracts.verdict import ReasonCode, StepRecorder
from sieve.gateway.crypto import (
    DOMAIN_DELEGATION,
    MAX_CHAIN_DEPTH,
    SigningKey,
    verify_delegation_chain,
)

ALL_CATEGORIES = frozenset({"outdoor", "kitchen", "books"})
ALL_CAPABILITIES = frozenset(
    {"catalog:read", "cart:write", "order:create", "payment:create"}
)

# One base instant for the whole module. Deriving each expiry from a fresh
# `utc_now()` would make a child issued microseconds after its parent outlive
# it — which the verifier correctly rejects as widening. See Authority.narrowed
# and ENGINEERING_LOG entry 2026-09-02 #1.
NOW = utc_now()


def authority(
    *,
    amount: int = 500_00,
    categories: frozenset[str] = ALL_CATEGORIES,
    capabilities: frozenset[str] = ALL_CAPABILITIES,
    hours: int = 24,
) -> Authority:
    return Authority(
        max_amount_paise=amount,
        categories=categories,
        capabilities=capabilities,
        expires_at=NOW + timedelta(hours=hours),
    )


def issue(issuer: SigningKey, subject: SigningKey, auth: Authority) -> Delegation:
    """Honestly issue a delegation from `issuer` to `subject`."""
    unsigned = Delegation(
        issuer=issuer.public_hex,
        subject=subject.public_hex,
        authority=auth,
        nonce=new_nonce(),
        issued_at=utc_now(),
        signature=b"",
    )
    return replace(unsigned, signature=issuer.sign(DOMAIN_DELEGATION, unsigned.to_body()))


@pytest.fixture
def keys() -> dict[str, SigningKey]:
    """human -> assistant -> tool, the realistic three-party shape."""
    return {
        "human": SigningKey.generate(),
        "assistant": SigningKey.generate(),
        "tool": SigningKey.generate(),
        "stranger": SigningKey.generate(),
    }


def check(chain, keys, *, roots=None, revoked=frozenset(), now=None):
    recorder = StepRecorder()
    return verify_delegation_chain(
        chain,
        trusted_roots=roots if roots is not None else frozenset({keys["human"].public_hex}),
        revoked_keys=revoked,
        now=now or utc_now(),
        recorder=recorder,
    )


# --------------------------------------------------------------------------
# The chain must accept what it should
# --------------------------------------------------------------------------


def test_valid_two_hop_chain_is_accepted(keys):
    chain = (
        issue(keys["human"], keys["assistant"], authority(amount=500_00)),
        issue(keys["assistant"], keys["tool"], authority(amount=200_00)),
    )
    effective, verdict = check(chain, keys)

    assert verdict is None
    assert effective is not None
    # Effective authority is the leaf's — safe only because narrowing is proven.
    assert effective.max_amount_paise == 200_00


def test_single_hop_chain_is_accepted(keys):
    chain = (issue(keys["human"], keys["assistant"], authority()),)
    effective, verdict = check(chain, keys)
    assert verdict is None
    assert effective.max_amount_paise == 500_00


def test_narrowing_on_every_dimension_at_once_is_accepted(keys):
    chain = (
        issue(keys["human"], keys["assistant"], authority()),
        issue(
            keys["assistant"],
            keys["tool"],
            authority(
                amount=100_00,
                categories=frozenset({"books"}),
                capabilities=frozenset({"catalog:read"}),
                hours=1,
            ),
        ),
    )
    _, verdict = check(chain, keys)
    assert verdict is None


# --------------------------------------------------------------------------
# Attack B7 — authority widening. The headline attack.
# --------------------------------------------------------------------------


def test_widened_amount_is_refused(keys):
    """A sub-agent grants itself a higher spend ceiling than it holds."""
    chain = (
        issue(keys["human"], keys["assistant"], authority(amount=500_00)),
        issue(keys["assistant"], keys["tool"], authority(amount=5_000_00)),
    )
    effective, verdict = check(chain, keys)

    assert effective is None
    assert verdict.reason_code is ReasonCode.AUTHORITY_WIDENED
    assert "amount ceiling widened" in verdict.evidence["violations"][0]


def test_widened_categories_are_refused(keys):
    chain = (
        issue(
            keys["human"],
            keys["assistant"],
            authority(categories=frozenset({"books"})),
        ),
        issue(
            keys["assistant"],
            keys["tool"],
            authority(categories=frozenset({"books", "kitchen"})),
        ),
    )
    _, verdict = check(chain, keys)
    assert verdict.reason_code is ReasonCode.AUTHORITY_WIDENED
    assert "categories widened" in verdict.evidence["violations"][0]


def test_widened_capabilities_are_refused(keys):
    chain = (
        issue(
            keys["human"],
            keys["assistant"],
            authority(capabilities=frozenset({"catalog:read"})),
        ),
        issue(
            keys["assistant"],
            keys["tool"],
            authority(capabilities=frozenset({"catalog:read", "payment:create"})),
        ),
    )
    _, verdict = check(chain, keys)
    assert verdict.reason_code is ReasonCode.AUTHORITY_WIDENED
    assert "capabilities widened" in verdict.evidence["violations"][0]


def test_extended_expiry_is_refused(keys):
    chain = (
        issue(keys["human"], keys["assistant"], authority(hours=1)),
        issue(keys["assistant"], keys["tool"], authority(hours=48)),
    )
    _, verdict = check(chain, keys)
    assert verdict.reason_code is ReasonCode.AUTHORITY_WIDENED
    assert "expiry extended" in verdict.evidence["violations"][0]


# --------------------------------------------------------------------------
# Attack B5/B6 — forged signatures and broken linkage
# --------------------------------------------------------------------------


def test_forged_link_signature_is_refused(keys):
    """A stranger signs a delegation claiming to be issued by the human."""
    honest = issue(keys["human"], keys["assistant"], authority())
    forged_unsigned = replace(honest, signature=b"")
    forged = replace(
        honest,
        signature=keys["stranger"].sign(DOMAIN_DELEGATION, forged_unsigned.to_body()),
    )

    _, verdict = check((forged,), keys)
    assert verdict.reason_code is ReasonCode.SIGNATURE_INVALID


def test_amount_tampered_after_signing_is_refused(keys):
    """Attack A2 at the delegation layer: flip the ceiling, keep the signature."""
    honest = issue(keys["human"], keys["assistant"], authority(amount=500_00))
    tampered = replace(honest, authority=authority(amount=5_000_00))

    _, verdict = check((tampered,), keys)
    assert verdict.reason_code is ReasonCode.SIGNATURE_INVALID


def test_broken_linkage_is_refused(keys):
    """Hop 2 is issued by a key that hop 1 never delegated to."""
    chain = (
        issue(keys["human"], keys["assistant"], authority()),
        issue(keys["stranger"], keys["tool"], authority(amount=100_00)),
    )
    _, verdict = check(chain, keys)
    assert verdict.reason_code is ReasonCode.CHAIN_BROKEN
    assert verdict.evidence["expected_issuer"] == keys["assistant"].public_hex


def test_unknown_root_is_refused(keys):
    """A perfectly valid chain rooted at a key this merchant never registered."""
    chain = (issue(keys["stranger"], keys["assistant"], authority()),)
    _, verdict = check(chain, keys)
    assert verdict.reason_code is ReasonCode.CHAIN_ROOT_UNKNOWN


# --------------------------------------------------------------------------
# Expiry, revocation, depth, cycles
# --------------------------------------------------------------------------


def test_expired_intermediate_link_is_refused(keys):
    """Attack B8: the leaf is live, but a link above it has lapsed."""
    chain = (
        issue(keys["human"], keys["assistant"], authority(hours=-1)),
        issue(keys["assistant"], keys["tool"], authority(hours=-2)),
    )
    _, verdict = check(chain, keys)
    assert verdict.reason_code is ReasonCode.LINK_EXPIRED
    assert verdict.evidence["hop"] == 0


def test_revoked_key_is_refused(keys):
    chain = (
        issue(keys["human"], keys["assistant"], authority()),
        issue(keys["assistant"], keys["tool"], authority(amount=100_00)),
    )
    _, verdict = check(
        chain, keys, revoked=frozenset({keys["assistant"].public_hex})
    )
    assert verdict.reason_code is ReasonCode.KEY_REVOKED


def test_chain_deeper_than_maximum_is_refused_before_crypto(keys):
    """Depth is bounded first so a forged chain cannot burn our CPU."""
    links = []
    current = keys["human"]
    for _ in range(MAX_CHAIN_DEPTH + 2):
        nxt = SigningKey.generate()
        links.append(issue(current, nxt, authority()))
        current = nxt

    _, verdict = check(tuple(links), keys)
    assert verdict.reason_code is ReasonCode.MALFORMED
    # Proof it short-circuited: no signature check ran.
    assert not any(step.name == "link_signatures" for step in verdict.steps)


def test_cyclic_chain_is_refused(keys):
    chain = (
        issue(keys["human"], keys["assistant"], authority()),
        issue(keys["assistant"], keys["tool"], authority(amount=200_00)),
        issue(keys["tool"], keys["assistant"], authority(amount=100_00)),
    )
    _, verdict = check(chain, keys)
    assert verdict.reason_code is ReasonCode.CHAIN_BROKEN
    assert keys["assistant"].public_hex in verdict.evidence["repeated"]


def test_empty_chain_is_refused(keys):
    _, verdict = check((), keys)
    assert verdict.reason_code is ReasonCode.MALFORMED


# --------------------------------------------------------------------------
# The evidence trail itself — the thing the UI renders
# --------------------------------------------------------------------------


def test_successful_verification_records_every_check(keys):
    """A pipeline that only logs failures cannot prove it ran the check that
    mattered. Passing steps are recorded too."""
    chain = (
        issue(keys["human"], keys["assistant"], authority()),
        issue(keys["assistant"], keys["tool"], authority(amount=200_00)),
    )
    recorder = StepRecorder()
    verify_delegation_chain(
        chain,
        trusted_roots=frozenset({keys["human"].public_hex}),
        revoked_keys=frozenset(),
        now=utc_now(),
        recorder=recorder,
    )

    names = [step.name for step in recorder.steps]
    assert names == [
        "chain_depth",
        "chain_root_trusted",
        "chain_acyclic",
        "chain_linkage",
        "keys_not_revoked",
        "links_unexpired",
        "link_signatures",
        "authority_narrowing",
    ]
    assert all(step.passed for step in recorder.steps)


# --------------------------------------------------------------------------
# Authority.narrowed — the ergonomics fix, which must not become a hole
# --------------------------------------------------------------------------


def test_narrowed_clamps_every_dimension(keys):
    parent = authority(
        amount=500_00,
        categories=frozenset({"books"}),
        capabilities=frozenset({"catalog:read"}),
        hours=1,
    )
    # Ask for more than the parent holds, on every axis at once.
    child = parent.narrowed(
        max_amount_paise=9_999_00,
        categories=frozenset({"books", "kitchen", "outdoor"}),
        capabilities=frozenset({"catalog:read", "payment:create"}),
        expires_at=NOW + timedelta(hours=72),
    )

    assert child.max_amount_paise == 500_00
    assert child.categories == frozenset({"books"})
    assert child.capabilities == frozenset({"catalog:read"})
    assert child.expires_at == parent.expires_at
    assert parent.narrowing_violations(child) == []


def test_narrowed_output_always_verifies_in_a_real_chain(keys):
    """The helper's whole purpose: a chain built with it cannot be rejected as
    widened, whatever the caller asked for."""
    parent_auth = authority(amount=500_00, hours=2)
    child_auth = parent_auth.narrowed(
        max_amount_paise=10_000_00, expires_at=NOW + timedelta(days=30)
    )
    chain = (
        issue(keys["human"], keys["assistant"], parent_auth),
        issue(keys["assistant"], keys["tool"], child_auth),
    )
    _, verdict = check(chain, keys)
    assert verdict is None


def test_narrowed_still_narrows_when_asked_for_less(keys):
    """Clamping must not accidentally become 'inherit everything'."""
    parent = authority(amount=500_00)
    child = parent.narrowed(max_amount_paise=50_00)
    assert child.max_amount_paise == 50_00


def test_refusal_explanation_is_human_readable(keys):
    """Every refusal must be a sentence a merchant could read. 'Denied' is not
    an acceptable output for a system claiming explainable money decisions."""
    chain = (
        issue(keys["human"], keys["assistant"], authority(amount=500_00)),
        issue(keys["assistant"], keys["tool"], authority(amount=5_000_00)),
    )
    _, verdict = check(chain, keys)

    assert verdict.explanation.endswith(".")
    assert len(verdict.explanation.split()) >= 6
    assert verdict.failed_step.name == "authority_narrowing"
