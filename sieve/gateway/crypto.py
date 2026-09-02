"""Ed25519 signing, and verification of delegation chains.

This module holds the project's novel core: `verify_delegation_chain`. It is the
answer to a question no surveyed competitor asks — not "does this agent hold a
valid mandate?" but "does this agent legitimately act for this human, through an
unbroken chain, without any hop having granted itself more than it held?"

Check order is deliberate and is itself a security property. Cheap, structural
checks run before expensive cryptographic ones, so an attacker cannot make the
gateway do signature verification on an arbitrarily long forged chain. Depth is
bounded before anything else happens at all.

No LLM is reachable from this module, and `tests/test_no_llm_in_policy.py`
fails the build if that ever stops being true.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sieve.contracts.canonical import CanonicalisationError, signing_payload
from sieve.contracts.mandate import Authority, Delegation
from sieve.contracts.verdict import ReasonCode, StepRecorder, Verdict

# A chain deeper than this is refused before any signature is checked. Real
# delegation is human -> assistant -> tool; anything approaching eight hops is
# either a mistake or an attempt to burn our CPU.
MAX_CHAIN_DEPTH = 8

DOMAIN_DELEGATION = "delegation"
DOMAIN_INTENT = "intent"


class SigningKey:
    """An Ed25519 keypair. Used by the human root, by agents, and by the
    attack corpus to forge things it should not be able to forge."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_hex(cls, private_hex: str) -> "SigningKey":
        return cls(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex)))

    @property
    def public_hex(self) -> str:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        return (
            self._private.public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
            .hex()
        )

    def sign(self, domain: str, body: Any) -> bytes:
        return self._private.sign(signing_payload(domain, body))


def verify_signature(
    public_hex: str, domain: str, body: Any, signature: bytes
) -> bool:
    """True iff `signature` is a valid signature by `public_hex` over `body`
    within `domain`.

    Returns False rather than raising on every failure mode — malformed key,
    malformed signature, unencodable body — because an attacker controls all
    three and must not be able to distinguish them or cause an exception to
    escape into a 500.
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        public_key.verify(signature, signing_payload(domain, body))
        return True
    except (InvalidSignature, ValueError, CanonicalisationError, TypeError):
        return False


def verify_delegation_chain(
    chain: tuple[Delegation, ...],
    *,
    trusted_roots: frozenset[str],
    revoked_keys: frozenset[str],
    now: datetime,
    recorder: StepRecorder,
) -> tuple[Authority | None, Verdict | None]:
    """Verify a delegation chain end to end.

    Returns `(effective_authority, None)` when the chain is sound, or
    `(None, verdict)` carrying the refusal when it is not.

    The effective authority is the leaf's authority. That is only safe *because*
    the narrowing invariant is enforced at every hop: with narrowing proven, the
    leaf is necessarily the intersection of everything above it.
    """
    # --- structural: depth, before any crypto ---------------------------------
    if not chain:
        recorder.record("chain_present", False, "delegation chain is empty")
        return None, recorder.refuse(
            ReasonCode.MALFORMED, "The request carried no delegation chain."
        )

    if len(chain) > MAX_CHAIN_DEPTH:
        recorder.record(
            "chain_depth",
            False,
            f"chain depth {len(chain)} exceeds maximum {MAX_CHAIN_DEPTH}",
            {"depth": len(chain), "max_depth": MAX_CHAIN_DEPTH},
        )
        return None, recorder.refuse(
            ReasonCode.MALFORMED,
            f"Delegation chain is {len(chain)} hops deep; the maximum is "
            f"{MAX_CHAIN_DEPTH}.",
        )

    recorder.record(
        "chain_depth",
        True,
        f"chain depth {len(chain)} within maximum {MAX_CHAIN_DEPTH}",
        {"depth": len(chain), "max_depth": MAX_CHAIN_DEPTH},
    )

    # --- the root must be a key we actually trust -----------------------------
    root = chain[0].issuer
    if root not in trusted_roots:
        recorder.record(
            "chain_root_trusted",
            False,
            "chain root is not a registered human key",
            {"root": root},
        )
        return None, recorder.refuse(
            ReasonCode.CHAIN_ROOT_UNKNOWN,
            "The chain does not begin at a human account this merchant knows.",
            {"root": root},
        )

    recorder.record(
        "chain_root_trusted", True, "chain root is a registered human key", {"root": root}
    )

    # --- no cycles: a key may appear as subject at most once -------------------
    # With narrowing enforced a cycle cannot gain authority, but it can still be
    # used to inflate depth and to confuse audit reading, so it is refused.
    subjects = [link.subject for link in chain]
    if len(set(subjects)) != len(subjects):
        duplicates = sorted({key for key in subjects if subjects.count(key) > 1})
        recorder.record(
            "chain_acyclic", False, "a key appears twice in the chain", {"repeated": duplicates}
        )
        return None, recorder.refuse(
            ReasonCode.CHAIN_BROKEN,
            "The delegation chain revisits the same key and is therefore cyclic.",
            {"repeated": duplicates},
        )

    recorder.record("chain_acyclic", True, "no key repeats in the chain")

    # --- linkage: each hop must hand off to the next --------------------------
    for index in range(len(chain) - 1):
        parent, child = chain[index], chain[index + 1]
        if parent.subject != child.issuer:
            recorder.record(
                "chain_linkage",
                False,
                f"link {index} hands off to {parent.subject[:16]}… but link "
                f"{index + 1} is issued by {child.issuer[:16]}…",
                {
                    "hop": index,
                    "expected_issuer": parent.subject,
                    "actual_issuer": child.issuer,
                },
            )
            return None, recorder.refuse(
                ReasonCode.CHAIN_BROKEN,
                f"Delegation hop {index + 1} was issued by a key that hop {index} "
                f"never delegated to.",
                {"hop": index, "expected_issuer": parent.subject, "actual_issuer": child.issuer},
            )

    recorder.record(
        "chain_linkage", True, f"all {len(chain) - 1} hand-offs link correctly"
    )

    # --- revocation -----------------------------------------------------------
    involved = {chain[0].issuer} | set(subjects)
    revoked = involved & revoked_keys
    if revoked:
        recorder.record(
            "keys_not_revoked", False, "a key in the chain is revoked", {"revoked": sorted(revoked)}
        )
        return None, recorder.refuse(
            ReasonCode.KEY_REVOKED,
            "A key in this delegation chain has been revoked.",
            {"revoked": sorted(revoked)},
        )

    recorder.record("keys_not_revoked", True, "no key in the chain is revoked")

    # --- expiry: every link must still be live --------------------------------
    for index, link in enumerate(chain):
        if link.authority.expires_at <= now:
            recorder.record(
                "links_unexpired",
                False,
                f"link {index} expired at {link.authority.expires_at.isoformat()}",
                {
                    "hop": index,
                    "expired_at": link.authority.expires_at.isoformat(),
                    "now": now.isoformat(),
                },
            )
            return None, recorder.refuse(
                ReasonCode.LINK_EXPIRED,
                f"Delegation hop {index} expired at "
                f"{link.authority.expires_at.isoformat()}.",
                {"hop": index, "expired_at": link.authority.expires_at.isoformat()},
            )

    recorder.record("links_unexpired", True, f"all {len(chain)} links are within validity")

    # --- signatures: now, and only now, do the expensive work -----------------
    for index, link in enumerate(chain):
        if not verify_signature(
            link.issuer, DOMAIN_DELEGATION, link.to_body(), link.signature
        ):
            recorder.record(
                "link_signatures",
                False,
                f"link {index} is not validly signed by its stated issuer",
                {"hop": index, "issuer": link.issuer},
            )
            return None, recorder.refuse(
                ReasonCode.SIGNATURE_INVALID,
                f"Delegation hop {index} carries an invalid signature.",
                {"hop": index, "issuer": link.issuer},
            )

    recorder.record(
        "link_signatures", True, f"all {len(chain)} link signatures verify"
    )

    # --- the narrowing invariant: authority may only shrink -------------------
    # This is attack B7's target, and the reason the leaf can be trusted as the
    # effective authority.
    for index in range(len(chain) - 1):
        parent, child = chain[index], chain[index + 1]
        violations = parent.authority.narrowing_violations(child.authority)
        if violations:
            recorder.record(
                "authority_narrowing",
                False,
                f"hop {index + 1} widened authority: {'; '.join(violations)}",
                {"hop": index + 1, "violations": violations},
            )
            return None, recorder.refuse(
                ReasonCode.AUTHORITY_WIDENED,
                f"Delegation hop {index + 1} granted more authority than it holds: "
                f"{violations[0]}.",
                {"hop": index + 1, "violations": violations},
            )

    recorder.record(
        "authority_narrowing",
        True,
        "authority narrows monotonically at every hop",
        {"hops_checked": max(0, len(chain) - 1)},
    )

    effective = chain[-1].authority
    return effective, None
