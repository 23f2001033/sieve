"""Gateway factories — build each attackable target from a shared World.

Both gateways are constructed with the SAME merchant id, catalog, clock and
trusted roots (all from the World), so the only variable in the differential is
the gateway's own logic. Fresh SQLite databases per build keep runs isolated and
reproducible.
"""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

from sieve.contracts.adapter import GatewayAdapter
from sieve.gateway.gateway import SieveGateway
from sieve.gateway.idempotency import SqliteIdempotencyStore
from sieve.gateway.ledger import SqliteLedger
from sieve.gateway.nonce import SqliteNonceStore
from sieve.naive.gateway import NaiveGateway
from sieve.suite.world import MERCHANT_ID, World


def _fresh_dir() -> Path:
    path = Path(tempfile.gettempdir()) / "sieve-corpus" / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=True)
    return path


def build_sieve(world: World, *, revoked: frozenset[str] = frozenset()) -> SieveGateway:
    d = _fresh_dir()
    return SieveGateway(
        catalog=world.catalog,
        nonce_store=SqliteNonceStore(str(d / "nonce.db")),
        idempotency_store=SqliteIdempotencyStore(str(d / "idem.db")),
        ledger=SqliteLedger(str(d / "ledger.db")),
        clock=world.clock,
        merchant_id=MERCHANT_ID,
        trusted_roots=world.trusted_roots,
        revoked_keys=revoked,
    )


def build_naive(world: World) -> NaiveGateway:
    return NaiveGateway(
        catalog=world.catalog,
        clock=world.clock,
        merchant_id=MERCHANT_ID,
    )


def all_targets(world: World) -> list[GatewayAdapter]:
    """Every gateway the corpus runs against. Razorpay's test-mode MCP would slot
    in here as a third target when credentials are present."""
    return [build_sieve(world), build_naive(world)]
