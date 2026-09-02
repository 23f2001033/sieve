"""The full attack corpus — 16 attacks in four families.

One list, assembled from the four family modules, so the runner, the API, and
the UI all read the same corpus. Adding an attack means adding it to its family
module; nothing here hardcodes a count.
"""

from __future__ import annotations

from sieve.suite.attacks.authorization import AUTHORIZATION_ATTACKS
from sieve.suite.attacks.budget_scope import BUDGET_SCOPE_ATTACKS
from sieve.suite.attacks.dataplane import DATAPLANE_ATTACKS
from sieve.suite.attacks.delegation import DELEGATION_ATTACKS

ALL_ATTACKS = [
    *AUTHORIZATION_ATTACKS,   # A1–A4  authorization integrity
    *DELEGATION_ATTACKS,      # B5–B8  delegation chain
    *BUDGET_SCOPE_ATTACKS,    # C9–C12 budget / scope / concurrency
    *DATAPLANE_ATTACKS,       # D13–D16 data plane & business rules
]
