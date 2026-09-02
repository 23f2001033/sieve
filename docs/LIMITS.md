# Limits

What SIEVE does not do, stated plainly. A three-day build that claimed production
readiness would be less trustworthy than one that names its own boundaries.

Everything here is a *known* limit with a *known* remedy — not a list of things I
didn't get to.

---

## Scale: single-node by design

The gateway is one process against one SQLite database in WAL mode. That is a
deliberate scope choice, and it is genuinely load-bearing for the correctness
claims: the idempotency guarantee rests on a `UNIQUE` constraint being the single
serialisation point, and the cumulative-budget check rests on an in-process lock
around authorise-and-commit.

Both of those break the moment there are two processes.

| Component | Single-node mechanism | What multi-node requires |
|---|---|---|
| Idempotency | `UNIQUE(idempotency_key)` insert | Sharded key space with consistent hashing, or a Redis/etcd compare-and-set; the claim must remain a single atomic decision |
| Cumulative budget | In-process lock around check-and-commit | A transactional counter per root authority, or optimistic concurrency with retry — a distributed read-modify-write |
| Nonce store | `PRIMARY KEY` insert | Same sharding problem, **plus** expiry garbage collection — nonces currently grow without bound |
| Ledger | Single-writer sequential hash chain | Batched commits over a Merkle Mountain Range, so appends don't serialise on one writer |
| Trace stream | In-process `asyncio` fan-out over SSE | A pub/sub bus (Redis Streams, Kafka); an SSE connection pins a client to one pod, so horizontal scale breaks the current model |

None of these are hard problems. They are simply not three-day problems, and
building half of each would have produced a system that is neither correct at one
node nor correct at many.

## The ledger is tamper-evident, not tamper-proof

Each entry's hash includes the previous entry's, so altering any past entry breaks
every hash after it and the verifier names the exact sequence number where the
chain first fails. That is real and demonstrated.

But an attacker with **database write access** can recompute the whole chain
forward from their edit and leave it internally consistent. Detection requires an
anchor the attacker cannot also rewrite. The production answer is to publish the
chain head to an append-only log outside the attacker's reach on a fixed cadence;
the cheap intermediate step is signing each entry with a gateway key, which raises
the bar from "database write" to "key compromise."

Neither is built. The verifier proves internal consistency, and that is all it
claims.

## Concurrency is proven within one process only

`tests/test_concurrency.py` releases 25 threads through a barrier onto a real
database and asserts exactly one charge. That is a genuine race, not a simulated
one, and it is stable across repeated runs.

It is still one process. The GIL means Python threads interleave at a coarser
grain than true parallelism would, so this demonstrates the mechanism is correct
under contention — not that it survives multi-process load. This is also why the
naive baseline "contains" the concurrent double-spend: its non-atomic
check-then-add happens to be serialised by the GIL. That result is reported as an
artifact of the harness rather than counted as a differential win.

## Single-tenant

There is one merchant. `merchant_id` is checked on every intent, but idempotency
keys and cumulative budgets are not namespaced per merchant. In a multi-tenant
deployment those namespaces are mandatory — an idempotency key collision across
tenants would let one merchant's request return another's outcome.

## Key lifecycle is minimal

Revocation is checked against a set supplied at request time; there is no
distribution mechanism, no propagation delay model, and no grace window. Keys
themselves do not expire — only the authorities they carry do.

The consequence worth stating: **if a human's root key is compromised, every
delegation beneath it is valid until each one expires.** A production system needs
root-key rotation with a re-issuance path, and an answer for in-flight mandates at
the moment of compromise. SIEVE has neither.

## The corpus is a proposal, not a standard

Sixteen attacks chosen to be mechanistically distinct. It is not exhaustive, and
there is no standards body to conform to — AP2 is a specification, not a test
suite with an authority behind it. A red-team agent that searches for attacks
outside the hand-written set is designed but not built; without it, the corpus
tests what I thought to test.

## Razorpay integration is shallow

Test-mode credentials are wired for order creation. Settlement objects are not
available in test mode at all, so nothing in this project claims to reconcile or
settle. The gateway sits in front of the payment API; it does not model the
downstream ledger of an actual PSP.

## The false-refusal rate is a policy choice, not a floor

SIEVE's ~1% comes almost entirely from one deliberate rule: if the catalog price
*drops* between quote and checkout, the transaction is refused, because the buyer
authorised specific terms and the terms changed. A merchant who would rather honour
the lower price should flip that rule — the rate would approach zero and nothing
about the security properties would change.

It is reported rather than tuned away because a false-refusal rate of exactly zero
on a corpus this size would say more about the corpus than about the gateway.
