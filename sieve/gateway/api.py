"""The HTTP surface — the real gateway behind a live API, and the glass-box UI.

This is what turns the engine into something a judge can watch. Every endpoint
runs the *actual* gateway code the tests exercise; nothing here is scripted:

  - POST /v1/purchase       an honest purchase through the real SIEVE gateway
  - POST /v1/attack/{id}    one corpus attack, live, against SIEVE + naive
  - POST /v1/run-corpus     the whole corpus, returning the real containment matrix
  - GET  /v1/ledger         the real hash-chained ledger + its integrity result
  - POST /v1/ledger/tamper-demo   tamper a scratch ledger and show detection
  - GET  /v1/trace          SSE stream of the real trace events each decision emits
  - GET  /                  the console UI

No LLM is reachable from the decision path this serves; the agents that DO use an
LLM (sieve/agents/) sit outside it and call these endpoints like any other client.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse

from sieve.contracts.trace import TraceEvent, events_for
from sieve.gateway.gateway import SieveGateway
from sieve.gateway.idempotency import SqliteIdempotencyStore
from sieve.gateway.inventory import Northlight, SystemClock
from sieve.gateway.ledger import SqliteLedger
from sieve.gateway.nonce import SqliteNonceStore
from sieve.naive.gateway import NaiveGateway
from sieve.suite.attacks import ALL_ATTACKS
from sieve.suite.benign.cases import benign_corpus
from sieve.suite.report import summary_json
from sieve.suite.runner import run_corpus
from sieve.suite.targets import build_naive, build_sieve
from sieve.suite.world import MERCHANT_ID, World

UI_FILE = Path(__file__).resolve().parent.parent.parent / "ui" / "console.html"

# The live corpus. The UI reads whatever is here, so the scoreboard reflects the
# real attack set rather than a hardcoded 16.
LIVE_ATTACKS = list(ALL_ATTACKS)
LIVE_BENIGN: list = []


class Broadcaster:
    """In-process fan-out for trace events. Each SSE client gets a queue; a
    decision publishes to all of them. Async-only, fed from the async handlers,
    so there is no cross-thread hazard."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    async def publish(self, event: TraceEvent) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass


class Demo:
    """Persistent gateway state for the live-purchase and ledger demonstrations.

    The corpus endpoints use their own isolated gateways (via run_corpus); this
    one persists across requests so the ledger accumulates and the demo has
    continuity."""

    def __init__(self) -> None:
        import tempfile
        import uuid

        d = Path(tempfile.gettempdir()) / "sieve-api" / uuid.uuid4().hex
        d.mkdir(parents=True, exist_ok=True)
        from sieve.gateway.razorpay import RazorpayTestMode

        self.world = World()
        self.ledger = SqliteLedger(str(d / "ledger.db"))
        self.rail = RazorpayTestMode()
        self.gateway = SieveGateway(
            payments=self.rail,
            catalog=self.world.catalog,
            nonce_store=SqliteNonceStore(str(d / "nonce.db")),
            idempotency_store=SqliteIdempotencyStore(str(d / "idem.db")),
            ledger=self.ledger,
            clock=SystemClock(),
            merchant_id=MERCHANT_ID,
            trusted_roots=self.world.trusted_roots,
        )


def create_app() -> FastAPI:
    app = FastAPI(title="SIEVE", version="0.1.0")
    bus = Broadcaster()
    demo = Demo()

    async def emit(intent_body: dict, verdict) -> None:
        for ev in events_for(intent_body, verdict):
            await bus.publish(ev)

    @app.get("/")
    async def index():
        return FileResponse(str(UI_FILE))

    @app.get("/v1/health")
    async def health():
        return {"ok": True, "attacks": len(LIVE_ATTACKS), "merchant": MERCHANT_ID,
                "razorpay": {"configured": demo.rail.configured,
                             "test_mode": demo.rail.is_test_mode}}

    @app.post("/v1/purchase")
    async def purchase(sku: str = "sku_tote"):
        # A legitimate two-hop purchase through the real gateway.
        w = demo.world
        chain = w.default_chain()
        real_sku = {"sku_tote": "TENT-2P", "sku_mug": "STOVE-CAN", "sku_lamp": "BAG-0C"}.get(sku, "TENT-2P")
        intent = w.intent(w.tool, chain, [w.item(real_sku)])
        verdict = demo.gateway.submit(intent)
        await emit(intent.to_body(), verdict)
        return JSONResponse(verdict.to_json())

    @app.post("/v1/agent/shop")
    async def agent_shop(goal: str = "Buy me a tent, and a mug if the budget allows."):
        """Let the LLM buyer agent shop, under a bounded mandate it cannot widen.

        Imported lazily: `sieve.agents` is a forbidden import for every module on
        the money path, and keeping it out of this file's top-level imports keeps
        that boundary obvious to a reader as well as to the test.
        """
        from fastapi.concurrency import run_in_threadpool

        from sieve.agents.buyer import build_session

        session = await run_in_threadpool(build_session)
        run = await run_in_threadpool(session["agent"].run, goal)

        for purchase in run.purchases:
            verdict_json = purchase.get("verdict")
            if not verdict_json:
                continue
            allowed = verdict_json.get("allowed")
            await bus.publish(TraceEvent(
                t=_now(),
                ev="AGENT_PURCHASE_ALLOWED" if allowed else "AGENT_PURCHASE_REFUSED",
                hash=(purchase.get("sku") or "")[:8].lower().ljust(8, "0"),
                v="ALLOW" if allowed else "REFUSE",
                detail=f"{purchase.get('sku')} x{purchase.get('quantity')} — "
                       f"{verdict_json.get('reason_code')}",
            ))
        return JSONResponse(run.to_json())

    @app.post("/v1/agent/redteam")
    async def agent_redteam(probes: int = 6):
        """Let the red-team agent hunt for holes the hand-written corpus missed.

        Sandboxed by construction: it attacks a throwaway gateway with the payment
        rail hard-wired off. `needs_review` counts probes the agent itself expected
        to be refused that were allowed — candidates for human review, never
        reported as confirmed vulnerabilities.
        """
        from fastapi.concurrency import run_in_threadpool

        from sieve.agents.redteam import RedTeamAgent

        agent = RedTeamAgent(max_probes=max(1, min(probes, 12)))
        run = await run_in_threadpool(agent.run)

        for probe in run.probes:
            await bus.publish(TraceEvent(
                t=_now(),
                ev="REDTEAM_PROBE_ALLOWED" if probe.allowed else "REDTEAM_PROBE_REFUSED",
                hash="redteam0", v="REFUSE" if not probe.allowed else "ALLOW",
                detail=f"{probe.description[:60]} — {probe.reason}",
            ))
        return JSONResponse(run.to_json())

    @app.get("/v1/attacks")
    async def attacks():
        """Corpus metadata, so the scoreboard can render the real attack set
        before anything has been run."""
        return [
            {"attack_id": a.attack_id, "family": a.family, "name": a.name,
             "expected": sorted(r.value for r in a.expected_reasons)}
            for a in LIVE_ATTACKS
        ]

    @app.post("/v1/attack/{attack_id}")
    async def run_one(attack_id: str):
        """Run ONE attack and return the real verification steps behind the
        verdict — this is what the glass box renders. Attacks that need several
        submissions (replay, aggregate budget, the concurrency race) report their
        result without a single step trace, which the UI states plainly."""
        attack = next((a for a in LIVE_ATTACKS if a.attack_id == attack_id), None)
        if attack is None:
            return JSONResponse({"error": f"unknown attack {attack_id}"}, status_code=404)

        w = World()
        sieve_gw = build_sieve(w)
        naive_gw = build_naive(w)

        payload: dict = {"attack_id": attack_id, "name": attack.name, "family": attack.family}
        try:
            verdict = attack.perform(sieve_gw, w)
            payload["sieve"] = verdict.to_json()
            await emit({"attack": attack_id}, verdict)
        except NotImplementedError:
            payload["sieve"] = None
            payload["note"] = "multi-submission attack — see result summary"

        # Fresh world for the naive run so neither gateway sees the other's state.
        w2 = World()
        result_sieve = attack.run(build_sieve(w2), w2)
        w3 = World()
        result_naive = attack.run(build_naive(w3), w3)
        payload["result"] = {
            "sieve": result_sieve.to_json(),
            "naive": result_naive.to_json(),
        }
        return JSONResponse(payload)

    @app.post("/v1/run-benign")
    async def run_benign(count: int = 120):
        """The false-refusal half of the metric. Separate from the attack run
        because it is the slow one — the attack corpus stays snappy for the demo."""
        report = run_corpus([], benign_corpus(count, seed=42))
        return JSONResponse(summary_json(report))

    @app.post("/v1/run-corpus")
    async def run():
        report = run_corpus(LIVE_ATTACKS, LIVE_BENIGN)
        # Stream a trace event per attack so the tail reflects the run.
        for aid, row in report.attack_matrix.items():
            res = row["SIEVE (reference)"]
            await bus.publish(
                TraceEvent(
                    t=_now(), ev="POLICY_REFUSED" if res.contained else "POLICY_ALLOWED",
                    hash=aid.lower().replace("m", "a") + "00", v="REFUSE" if res.contained else "ALLOW",
                    detail=f"{aid} {res.actual_reason}",
                )
            )
        return JSONResponse(report.to_json())

    @app.get("/v1/ledger")
    async def ledger():
        entries = [e.to_json() for e in demo.ledger.entries()]
        return {"entries": entries, "integrity": demo.ledger.verify().to_json()}

    @app.post("/v1/ledger/tamper-demo")
    async def tamper_demo():
        """Build a scratch ledger, append real entries, verify (valid), then
        tamper one row and verify again (broken). Returns both so the UI can show
        detection without touching the live ledger."""
        import sqlite3
        import tempfile
        import uuid

        d = Path(tempfile.gettempdir()) / "sieve-tamper" / uuid.uuid4().hex
        d.mkdir(parents=True, exist_ok=True)
        scratch = SqliteLedger(str(d / "scratch.db"))
        for i in range(8):
            scratch.append("allow", {"seq_demo": i, "amount_paise": 1200_00, "sku": "TENT-2P"})
        before = scratch.verify().to_json()

        # Tamper entry #4's body directly in the DB — the kind of edit a DB-write
        # attacker would make. The chained hash no longer matches.
        conn = sqlite3.connect(str(d / "scratch.db"))
        conn.execute("UPDATE ledger SET body_json = ? WHERE seq = 4",
                     (json.dumps({"seq_demo": 4, "amount_paise": 120000_00, "sku": "TENT-2P"}),))
        conn.commit()
        conn.close()
        after = scratch.verify().to_json()
        return {"before": before, "after": after, "tampered_seq": 4}

    @app.get("/v1/trace")
    async def trace():
        async def stream():
            q = bus.subscribe()
            try:
                # greet so the client sees the stream is live immediately
                yield {"data": json.dumps(TraceEvent(_now(), "STREAM_OPEN", "00000000", "PROV", "trace attached").to_json())}
                while True:
                    ev: TraceEvent = await q.get()
                    yield {"data": json.dumps(ev.to_json())}
            finally:
                bus.unsubscribe(q)

        return EventSourceResponse(stream())

    return app


def _now() -> str:
    from datetime import datetime, timezone
    d = datetime.now(timezone.utc).astimezone()
    return f"{d.hour:02d}:{d.minute:02d}:{d.second:02d}.{d.microsecond // 1000:03d}"


app = create_app()
