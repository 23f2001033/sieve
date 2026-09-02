"""Canonical binary serialisation — the foundation every signature rests on.

Signatures are computed over *this* encoding, never over JSON. JSON is used only
for transport.

That choice is deliberate, and it is the whole answer to attack A3
(canonicalisation confusion). JSON has no single canonical form:

  - key order is unconstrained, so one document has many byte representations;
  - duplicate keys are handled inconsistently — some parsers take the first,
    some the last, some error — so signer and verifier can disagree about what
    document they even looked at;
  - unicode has multiple normal forms, so "café" can be two different byte
    strings that render identically;
  - numbers admit leading zeros, exponents, and float ambiguity.

Each of those is a way to make the verifier check a signature over one document
while acting on another. The naive gateway in `sieve/naive/` signs over
`json.dumps(...)` and fails A3 for exactly this reason.

The encoding below is type-tagged and length-prefixed, which makes it
*injective*: every value has exactly one byte representation, and no encoding is
a prefix of another. Distinct inputs therefore always produce distinct output,
so a signature binds to precisely one document.

Floats are rejected outright. Money is integer paise, everywhere, always.
"""

from __future__ import annotations

import hashlib
import unicodedata
from typing import Any

# Bumping this string invalidates every signature ever produced. That is the
# point: it is the version boundary for the signing format itself.
FORMAT_VERSION = b"SIEVE-canonical-v1\x00"

TAG_NULL = b"\x00"
TAG_FALSE = b"\x01"
TAG_TRUE = b"\x02"
TAG_INT = b"\x03"
TAG_STR = b"\x04"
TAG_BYTES = b"\x05"
TAG_LIST = b"\x06"
TAG_MAP = b"\x07"
TAG_SET = b"\x08"

_LENGTH_BYTES = 8
_INT_BYTES = 8
_INT_MIN = -(2 ** (_INT_BYTES * 8 - 1))
_INT_MAX = 2 ** (_INT_BYTES * 8 - 1) - 1


class CanonicalisationError(ValueError):
    """A value cannot be canonically encoded.

    Raised rather than coerced. A value we cannot represent unambiguously is a
    value we must not sign.
    """


def _length(n: int) -> bytes:
    if n < 0 or n >= 2 ** (_LENGTH_BYTES * 8):
        raise CanonicalisationError(f"length out of range: {n}")
    return n.to_bytes(_LENGTH_BYTES, "big")


def canonical_bytes(value: Any) -> bytes:
    """Encode `value` to its single canonical byte representation.

    Supported: None, bool, int, str, bytes, list/tuple, dict (str keys),
    frozenset/set. Everything else — floats included — raises.
    """
    # bool before int: bool is a subclass of int in Python, and conflating them
    # would let True and 1 share an encoding.
    if value is None:
        return TAG_NULL
    if value is True:
        return TAG_TRUE
    if value is False:
        return TAG_FALSE

    if isinstance(value, int):
        if not (_INT_MIN <= value <= _INT_MAX):
            # Relevant to attack D14: an amount that overflows is refused at the
            # encoder rather than silently wrapping somewhere downstream.
            raise CanonicalisationError(
                f"integer out of range for {_INT_BYTES}-byte encoding: {value}"
            )
        return TAG_INT + value.to_bytes(_INT_BYTES, "big", signed=True)

    if isinstance(value, str):
        # NFC-normalise so visually identical strings encode identically, and
        # so a verifier cannot be shown a different normal form than the signer.
        encoded = unicodedata.normalize("NFC", value).encode("utf-8")
        return TAG_STR + _length(len(encoded)) + encoded

    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return TAG_BYTES + _length(len(raw)) + raw

    if isinstance(value, (list, tuple)):
        parts = [canonical_bytes(item) for item in value]
        return TAG_LIST + _length(len(parts)) + b"".join(parts)

    if isinstance(value, dict):
        encoded_pairs = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalisationError(
                    f"map keys must be str, got {type(key).__name__}"
                )
            encoded_pairs.append((canonical_bytes(key), canonical_bytes(item)))
        # Sorting by encoded key makes order independent of insertion order.
        # Duplicate keys are impossible in a dict, but a *decoder* elsewhere
        # might accept them, so we assert distinctness explicitly.
        encoded_pairs.sort(key=lambda pair: pair[0])
        keys = [pair[0] for pair in encoded_pairs]
        if len(set(keys)) != len(keys):
            raise CanonicalisationError("duplicate map key after encoding")
        body = b"".join(k + v for k, v in encoded_pairs)
        return TAG_MAP + _length(len(encoded_pairs)) + body

    if isinstance(value, (frozenset, set)):
        parts = sorted(canonical_bytes(item) for item in value)
        if len(set(parts)) != len(parts):
            raise CanonicalisationError("duplicate set member after encoding")
        return TAG_SET + _length(len(parts)) + b"".join(parts)

    if isinstance(value, float):
        raise CanonicalisationError(
            "floats are not encodable — money is integer paise. "
            f"got {value!r}"
        )

    raise CanonicalisationError(f"unencodable type: {type(value).__name__}")


def signing_payload(domain: str, value: Any) -> bytes:
    """Bytes to sign for `value` within `domain`.

    The domain tag is the defence against cross-protocol signature reuse: a
    signature over a delegation must not verify as a signature over an intent,
    even if the two bodies happen to encode identically. Without this, an
    attacker who obtains any signed object could replay it as a different kind
    of object.
    """
    return FORMAT_VERSION + canonical_bytes(domain) + canonical_bytes(value)


def canonical_digest(domain: str, value: Any) -> bytes:
    """SHA-256 over the signing payload. Used for ledger entries and IDs."""
    return hashlib.sha256(signing_payload(domain, value)).digest()
