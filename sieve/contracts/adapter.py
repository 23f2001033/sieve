"""The GatewayAdapter protocol — the seam the attack corpus runs against.

The whole point of an adapter is that the corpus does not know or care which
gateway it is attacking. The same 16 attacks and the same benign corpus run,
unchanged, against:

  - SIEVE's reference gateway (sieve/gateway/gateway.py),
  - the naive baseline (sieve/naive/gateway.py),
  - and, where test-mode credentials exist, a wrapper over Razorpay's own MCP
    surface.

That is what makes the differential result honest: nobody tuned the corpus to
one implementation, because the corpus cannot see the implementation. A gateway
either contains an attack or it does not, and the runner records which, per
target, with no special-casing.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from sieve.contracts.mandate import Intent
from sieve.contracts.verdict import Verdict


@runtime_checkable
class GatewayAdapter(Protocol):
    """Anything the corpus can attack.

    `name` labels the target in the report. `submit` is the single entry point:
    it takes a fully-formed intent and returns a verdict, having applied whatever
    checks that gateway applies. It must be safe to call concurrently — the
    double-spend attack depends on it.
    """

    @property
    def name(self) -> str: ...

    def submit(self, intent: Intent) -> Verdict: ...
