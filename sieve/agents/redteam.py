"""The red-team agent — an LLM that attacks this gateway, looking for holes the
hand-written corpus missed.

The 16-attack corpus tests what *I* thought to test. That is its ceiling. This
agent exists to probe past it: it is told how the gateway works and invited to
construct delegation chains and intents that should not be honoured, including
shapes I did not anticipate.

**Defence-only, and sandboxed by construction.** It attacks a throwaway gateway
built for the run, with the payment rail hard-wired to `NullRail` — it cannot
reach Razorpay, the live gateway, the filesystem, or the network. Its only verb
is `probe`, which builds an intent from a structured spec and submits it. It
cannot execute code, and there is nothing here that could be pointed at somebody
else's system.

**On honesty of findings.** A probe that comes back ALLOWED is a *candidate*
finding, not a confirmed vulnerability — plenty of legitimate purchases are
correctly allowed. The runner separates the two: probes the agent itself declared
as "should be refused" that were nonetheless allowed are surfaced as
`needs_review`. Every one is then read by a human before it is called a hole.
Claiming an unreviewed count as "vulnerabilities found" would be the same
overclaiming this whole project exists to avoid.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from sieve.agents.llm import LLMClient, LLMUnavailable
from sieve.contracts.mandate import LineItem, new_nonce
from sieve.gateway.crypto import SigningKey
from sieve.suite.world import World

INSTRUCTIONS = """You are a security researcher red-teaming a payment gateway called \
SIEVE. Your job is to find purchases it wrongly ALLOWS.

How the gateway works. A buyer agent presents a DELEGATION CHAIN: a sequence of \
signed hops starting from a human's registered root key, each hop granting authority \
to the next. The gateway checks, in order: chain depth, that the root is trusted, \
that the chain is acyclic, that each hop hands off to the next, that no key is \
revoked, that no hop has expired, that every hop's signature verifies, and finally \
the NARROWING INVARIANT — a hop may never grant more authority than it holds \
(amount ceiling, product categories, capabilities, expiry may only shrink). It then \
checks capability, recomputes the order total from its own catalog, and enforces \
category scope and a CUMULATIVE budget ceiling.

Use the `probe` tool to construct chains and orders and submit them. You control \
each hop's authority, so you can try to widen it. You can also misstate the order \
total, reuse a nonce, or sign with the wrong key.

For every probe, set `expectation` honestly to what SHOULD happen: "refuse" if a \
correct gateway must reject it, "allow" if it is a legitimate purchase. Being \
accurate here matters more than finding a hole — a probe you mislabel is worse than \
useless, because it produces a false finding.

Be inventive. Obvious single-rule violations are already covered by an existing \
test suite; look for COMBINATIONS, edge cases and orderings that might slip \
between checks. When you are done, summarise what you tried and whether anything \
got through that should not have.

THE MERCHANT'S CATALOG — these are the only SKUs and the only categories that \
exist. Ordering a category the chain does not permit is refused, so start from a \
chain whose categories actually cover what you buy:
{catalog}

Capabilities are exactly: catalog:read, cart:write, order:create, payment:create, \
refund:create. A purchase needs order:create AND payment:create.

Start with ONE probe you expect to be ALLOWED, to confirm your chain is otherwise \
valid. If your baseline is refused, fix it before hunting — a probe that fails for \
an unrelated reason tests nothing."""


def _catalog_brief() -> str:
    """The agent cannot attack what it cannot see. Built from the real catalog so
    it can never drift from what the gateway actually sells."""
    from sieve.gateway.inventory import CATALOG_PRODUCTS

    return "\n".join(
        f"  {p.sku:10} category={p.category:8} price={p.price_paise} paise"
        for p in CATALOG_PRODUCTS
    )

TOOLS: list[dict[str, Any]] = [
    {"type": "function", "function": {
        "name": "probe",
        "description": "Build a delegation chain and an order from this spec, submit it, and return the gateway's verdict.",
        "parameters": {"type": "object", "properties": {
            "description": {"type": "string", "description": "What this probe tests, in one line."},
            "expectation": {"type": "string", "enum": ["refuse", "allow"],
                            "description": "What a CORRECT gateway should do. Be honest."},
            "hops": {
                "type": "array",
                "description": "Delegation hops from the human root outward. Each may widen authority — that is the attack.",
                "items": {"type": "object", "properties": {
                    "max_amount_paise": {"type": "integer"},
                    "categories": {"type": "array", "items": {"type": "string"}},
                    "capabilities": {"type": "array", "items": {"type": "string"}},
                    "expiry_hours": {"type": "number"},
                }, "required": ["max_amount_paise"]},
            },
            "sku": {"type": "string"},
            "quantity": {"type": "integer", "minimum": 1, "maximum": 50},
            "stated_total_paise": {"type": "integer",
                                   "description": "Optional. Misstate the order total."},
            "reuse_nonce": {"type": "boolean",
                            "description": "Reuse the previous probe's nonce (replay)."},
            "sign_with": {"type": "string", "enum": ["leaf", "stranger", "root"],
                          "description": "Which key signs the intent. 'leaf' is correct."},
            "break_linkage": {"type": "boolean",
                              "description": "Issue the last hop from an undelegated key."},
        }, "required": ["description", "expectation", "hops", "sku", "quantity"]}}},
]

CATALOG_SKUS = ["TENT-2P", "BAG-0C", "STOVE-CAN", "FILTER-SQ", "TRAILMUG", "MAP-IN"]
KNOWN_CAPS = ["catalog:read", "cart:write", "order:create", "payment:create", "refund:create"]


@dataclass
class Probe:
    description: str
    expectation: str
    allowed: bool
    reason: str
    spec: dict[str, Any]

    @property
    def needs_review(self) -> bool:
        """Allowed despite the agent itself saying it should be refused."""
        return self.expectation == "refuse" and self.allowed

    def to_json(self) -> dict[str, Any]:
        return {"description": self.description, "expectation": self.expectation,
                "allowed": self.allowed, "reason": self.reason,
                "needs_review": self.needs_review, "spec": self.spec}


@dataclass
class RedTeamRun:
    probes: list[Probe] = field(default_factory=list)
    summary: str = ""
    stopped_by: str = "completed"

    @property
    def needs_review(self) -> list[Probe]:
        return [p for p in self.probes if p.needs_review]

    def to_json(self) -> dict[str, Any]:
        return {"probes": [p.to_json() for p in self.probes],
                "probe_count": len(self.probes),
                "needs_review_count": len(self.needs_review),
                "summary": self.summary, "stopped_by": self.stopped_by}


class RedTeamAgent:
    def __init__(self, *, client: LLMClient | None = None, max_probes: int = 12,
                 max_steps: int = 14) -> None:
        self.client = client or LLMClient()
        self.max_probes = max_probes
        self.max_steps = max_steps
        self._last_nonce: str | None = None
        self._world: World | None = None
        self._gateway = None

    def _ensure_target(self) -> None:
        """One world and ONE gateway for the whole run.

        This was originally a fresh gateway per probe, and the agent immediately
        exposed why that was wrong: it reported a successful nonce replay. The
        replay "succeeded" only because each probe hit a brand-new gateway that
        had never seen the nonce — a hole in the harness, not the gateway. Any
        stateful attack (replay, cumulative budget evasion) is untestable against
        a target that forgets between attempts. A real attacker probes one
        gateway repeatedly, so the harness does too.
        """
        from sieve.suite.targets import build_sieve

        if self._world is None:
            self._world = World()
            self._gateway = build_sieve(self._world)  # NullRail: cannot reach Razorpay

    def _build_and_submit(self, spec: dict[str, Any]) -> tuple[bool, str]:
        """Construct exactly what the spec asks for — including invalid shapes —
        and submit it to the run's sandboxed gateway (no payment rail)."""
        self._ensure_target()
        world, gateway = self._world, self._gateway

        hops_spec = spec.get("hops") or [{"max_amount_paise": 500_00}]
        keys = [world.human] + [SigningKey.generate() for _ in range(len(hops_spec))]

        chain = []
        for i, hop in enumerate(hops_spec):
            cats = hop.get("categories")
            caps = hop.get("capabilities")
            authority = world.authority(
                amount_paise=int(hop.get("max_amount_paise", 500_00)),
                categories=frozenset(cats) if cats else frozenset({"outdoor", "kitchen", "books"}),
                capabilities=frozenset(c for c in (caps or KNOWN_CAPS) if c in KNOWN_CAPS)
                             or frozenset({"catalog:read", "order:create", "payment:create"}),
                hours=float(hop.get("expiry_hours", 24)),
            )
            issuer = keys[i]
            if spec.get("break_linkage") and i == len(hops_spec) - 1 and i > 0:
                issuer = world.stranger  # a key the previous hop never delegated to
            chain.append(world.issue(issuer, keys[i + 1], authority))

        sku = spec.get("sku") if spec.get("sku") in CATALOG_SKUS else "TENT-2P"
        product = world.catalog.product(sku)
        quantity = max(1, min(int(spec.get("quantity", 1)), 50))
        item = LineItem(sku=product.sku, category=product.category,
                        quantity=quantity, unit_price_paise=product.price_paise)

        signer = {"leaf": keys[len(hops_spec)], "stranger": world.stranger,
                  "root": world.human}.get(spec.get("sign_with", "leaf"), keys[len(hops_spec)])

        nonce = (self._last_nonce if spec.get("reuse_nonce") and self._last_nonce
                 else new_nonce())
        intent = world.intent(signer, tuple(chain), [item],
                              total_paise=spec.get("stated_total_paise"), nonce=nonce)

        if spec.get("reuse_nonce") and self._last_nonce:
            pass  # deliberately reusing
        else:
            self._last_nonce = nonce

        verdict = gateway.submit(intent)
        return verdict.allowed, verdict.reason_code.value

    def run(self, brief: str = "Find a purchase this gateway wrongly allows.") -> RedTeamRun:
        run = RedTeamRun()
        messages = [
            {"role": "system", "content": INSTRUCTIONS.format(catalog=_catalog_brief())},
            {"role": "user", "content": brief},
        ]

        for _ in range(self.max_steps):
            try:
                msg = self.client.chat(messages, tools=TOOLS, temperature=0.7)
            except LLMUnavailable as exc:
                run.summary = f"Model unavailable: {exc}"
                run.stopped_by = "llm_unavailable"
                return run

            calls = msg.get("tool_calls") or []
            messages.append({"role": "assistant", "content": msg.get("content") or "",
                             **({"tool_calls": calls} if calls else {})})

            if not calls:
                run.summary = msg.get("content") or ""
                return run

            for call in calls:
                try:
                    args = json.loads(call.get("function", {}).get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                try:
                    allowed, reason = self._build_and_submit(args)
                except Exception as exc:
                    allowed, reason = False, f"probe_error:{type(exc).__name__}"

                probe = Probe(description=str(args.get("description", ""))[:200],
                              expectation=args.get("expectation", "refuse"),
                              allowed=allowed, reason=reason, spec=args)
                run.probes.append(probe)
                messages.append({"role": "tool", "tool_call_id": call.get("id", ""),
                                 "content": json.dumps({"allowed": allowed, "reason": reason})})

            if len(run.probes) >= self.max_probes:
                run.stopped_by = "max_probes"
                messages.append({"role": "user",
                                 "content": "Probe budget spent. Summarise what you tried "
                                            "and whether anything got through."})
                try:
                    final = self.client.chat(messages)
                    run.summary = final.get("content") or ""
                except LLMUnavailable:
                    run.summary = "(probe budget spent; no summary returned)"
                return run

        run.stopped_by = "max_steps"
        return run


def main() -> int:
    import sys
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    agent = RedTeamAgent()
    print(f"model: {agent.client.model}\nred-teaming SIEVE…\n")
    run = agent.run()
    for i, p in enumerate(run.probes, 1):
        flag = "  ← NEEDS REVIEW" if p.needs_review else ""
        got = "ALLOWED" if p.allowed else f"refused ({p.reason})"
        print(f"  {i:2}. [{p.expectation:6}] {p.description[:70]}\n      → {got}{flag}")
    print(f"\nprobes: {len(run.probes)} · needs review: {len(run.needs_review)} "
          f"· stopped: {run.stopped_by}")
    print(f"\nagent summary:\n{run.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
