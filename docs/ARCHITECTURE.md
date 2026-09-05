# Architecture

Why SIEVE is shaped the way it is. Every section names the alternative that was
rejected, because a design decision without its discarded alternative is just a
description.

---

## 1. The governing idea

An AI agent shopping on a merchant's behalf is a **counterparty the merchant did
not write, cannot audit, and must not trust**. Razorpay's MCP server already lets
an agent create orders and capture payments; it assumes the agent calling it is
yours. SIEVE is the layer that makes that surface safe to expose to an agent that
isn't.

Everything below follows from one asymmetry:

```
    LLM (buyer agent)  ──proposes──▶   DETERMINISTIC GATEWAY  ──disposes──▶  money
       judgment, language                  rules, crypto, arithmetic
```

**The agent proposes; the gateway disposes.** A money decision made by a model is
a decision you cannot reproduce, audit, or defend to a regulator. Same input, same
verdict, forever — that is not achievable with a model in the path, so there isn't
one.

**Rejected:** a multi-agent design where a merchant agent negotiates with a buyer
agent. It demos beautifully and is indefensible. Two models agreeing is not an
authorization; it's a coincidence you can't reproduce.

---

## 2. The layers

```
┌──────────────────────────────────────────────────────────────┐
│  sieve/agents/     buyer · red-team          ← ONLY LLM here │
│                    tools, guardrails, loop bounds            │
└───────────────────────────┬──────────────────────────────────┘
                            │ proposes an Intent (signed)
┌───────────────────────────▼──────────────────────────────────┐
│  sieve/gateway/    THE CHOKE POINT — no LLM, CI-enforced      │
│   crypto.py        Ed25519 · delegation-chain verification    │
│   policy.py        the decision: budget, scope, totals, stock │
│   nonce · idempotency · ledger · inventory                    │
│   razorpay.py      payment rail — reached ONLY after ALLOW    │
└───────────────────────────┬──────────────────────────────────┘
                            │ Verdict (allow/refuse + full step trail)
┌───────────────────────────▼──────────────────────────────────┐
│  sieve/suite/      16 attacks · 1000 benign · runner · report │
│  sieve/naive/      the honest baseline, for the differential  │
│  ui/console.html   the glass box                              │
└──────────────────────────────────────────────────────────────┘
```

`sieve/config.py` sits outside both the agents and the money path — shared ground
for `.env` loading, so the payment rail never has to import the agents package to
read a credential. That file exists *because* the guard caught me routing through
`sieve/agents/llm.py` (engineering log #11).

---

## 3. The decisions

### 3.1 Signing over canonical binary, not JSON

**Chosen:** a type-tagged, length-prefixed binary encoding. One document, exactly
one byte string.

**Rejected:** signing over `json.dumps(..., sort_keys=True)` — the obvious choice,
and what the naive baseline does.

**Why:** JSON has no canonical form. Key order, duplicate keys, unicode normal
forms, and number formatting all admit ambiguity, and every one of them is a way
to make a verifier check a signature over one document while acting on another.
Sorting keys fixes one of four problems. Rather than defend each ambiguity, the
encoding removes the class: type tags mean `"1"` and `1` and `True` can never
collide; length prefixes mean `{"ab":"c"}` and `{"a":"bc"}` cannot; NFC
normalisation means the signer and verifier agree on what a string *is*. Floats
are rejected outright — money is integer paise, everywhere.

**Cost:** the format is ours, so nothing else can verify our signatures without
implementing it. Acceptable for a reference implementation; a real standard would
adopt JCS (RFC 8785) instead of inventing one.

### 3.2 Multi-hop delegation with a monotonic narrowing invariant

**Chosen:** a chain `human → assistant → sub-agent`, where each hop may only
**shrink** authority — amount ceilings down, category and capability sets subset,
expiry earlier.

**Rejected:** a single signed mandate, which is what AP2 specifies and what every
surveyed competitor implements.

**Why:** real agent stacks delegate. An assistant spawns a tool; the tool acts.
A single mandate can only answer "does this agent hold authority?" — never "does
this agent legitimately act *for this human*, through an unbroken chain?" The
narrowing invariant is what makes the leaf trustworthy: with it proven at every
hop, the leaf's authority *is* the intersection of everything above it, so the
policy engine can read one object instead of intersecting the chain.

**The subtle payoff:** because expiry narrows monotonically, a valid leaf
*implies* every ancestor is valid. Checking only the leaf's expiry is therefore
sufficient — a property that falls out of the invariant rather than being
separately enforced.

**Not claimed as novel.** AP2 is prior art for signed agent-payment mandates. The
multi-hop narrowing is an extension, not an invention.

### 3.3 Check order is a security property

Verification runs: depth bound → root trusted → acyclic → linkage → revocation →
expiry → **signatures** → narrowing.

**Rejected:** verifying signatures first, which reads more naturally ("is this
authentic before I look at it?").

**Why:** signature verification is the only expensive step. Putting it last behind
cheap structural checks means a forged 20-link chain is rejected **without
verifying a single signature** — attack B8 (the depth bomb) exists to prove that
ordering holds. An attacker must not be able to make you do expensive work before
you reject them.

### 3.4 The policy engine never reads product text

**Chosen:** price, category and stock come from the merchant's catalog. The
product description is opaque bytes on the money path.

**Rejected:** an LLM classifier that screens descriptions for injection attempts.

**Why:** this is the prompt-injection defence, and it is architectural rather than
detective. There is no classifier to fool because there is no classifier. Adding
one would *reintroduce* precisely the surface the attack targets — a model reading
attacker-controlled text, inside the trusted path. Attack D13 models a buyer agent
that was successfully fooled and submits a ₹0 intent; the gateway recomputes from
the catalog and refuses. Containment here is the **absence of any effect**.

### 3.5 Nonces and idempotency are separate mechanisms

This is the single most consequential decision in the project.

| | Nonce store | Idempotency store |
|---|---|---|
| Question | "Have I seen this request before?" | "Did I already decide this?" |
| On a duplicate | **Refuse** — replay attack | **Replay the first outcome** |
| Serves | attack A1 | the honest retry after a timeout |

**Rejected:** one mechanism, which is what the naive baseline does — a nonce set
that refuses anything it has seen.

**Why it matters:** they pull in opposite directions. A customer whose connection
drops and whose client retries is *indistinguishable* from a replay attacker at
the nonce layer. Conflating them means the attack is caught and the customer is
punished. That is where the naive gateway's **161/1000 false refusals** come from
— **every one is an honest retry misread as an attack.**

This is why SIEVE is not "more secure at the cost of friction." It is more secure
*and* far kinder: 16/16 vs 3/16 contained, ~1% vs 16% wrongly refused. Separating
the two mechanisms is what buys both at once.

### 3.6 Cumulative budget, not per-order caps

**Chosen:** the ceiling is checked against `spent_so_far + this_order`, under a
lock that covers check-and-commit atomically.

**Rejected:** a per-order cap, the natural reading of "max_amount".

**Why:** attack C9 — a ₹500 authority spent as two ₹349 orders. Each is under the
ceiling; their sum is not. A per-order check passes both.

### 3.7 The payment rail sits strictly downstream of ALLOW

A refused intent produces **no Razorpay call at all**, and the ledger records
`razorpay: {"status": "no_call"}` — the absence of a payment is itself audited,
not merely implied. `tests/test_payment_rail.py` counts calls with a spy rail, so
"a refused intent never reaches the payment API" is measured rather than intended.

The rail also refuses outright any key without an `rzp_test_` prefix. An
autonomous agent creates these orders; a live key reached by accident would move
real money, so that is a hard stop rather than a warning.

### 3.8 Verdicts carry their whole reasoning

**Chosen:** every verdict carries the ordered list of checks that ran — **passing
ones included** — each with what it compared and how long it took.

**Rejected:** returning a boolean and a reason code.

**Why:** the UI's glass box renders exactly this structure, so the evidence a
judge watches is the evidence the engine acted on, not a re-narration. And
recording passing steps matters: a pipeline that logs only failures cannot prove
it *ran* the check that mattered.

### 3.9 SQLite in WAL mode, single node

**Chosen:** one process, one SQLite file. The `UNIQUE` constraint on
`idempotency_key` **is** the serialisation point; the database resolves the race,
so there is no application-level lock to get wrong.

**Rejected:** Postgres or Redis, which would scale.

**Why:** a three-day build that is correct at one node beats one that is half-built
at many. Every consequence is named in [LIMITS.md](LIMITS.md) with its remedy —
and `render.yaml` pins `numInstances: 1` with the reasoning inline, so nobody
scales it by accident and silently breaks exactly-once.

### 3.10 The naive baseline gets the cryptography right

**Chosen:** the baseline verifies signatures correctly, with the same canonical
scheme, and is naive only about *authorization logic*.

**Rejected:** my first version, which signed over `json.dumps` — and therefore
could not verify any SIEVE-signed mandate, rejected everything, and scored a
meaningless 4/4.

**Why:** a gateway that refuses everyone "contains" every attack the way a brick
contains a burglar. Making the baseline crypto-correct means the attacks it lets
through are lapses in *authorization reasoning* — which is what real
implementations get wrong, and what SIEVE actually contributes.

### 3.11 Two corpora, always reported together

Containment alone is meaningless. A gateway that refuses everything scores 16/16.
So the false-refusal rate on 1,000 legitimate transactions is reported beside it,
with a **Wilson 95% interval** — a bare percentage on a few hundred cases
overstates its own precision.

The ~1% is dominated by one deliberate rule: a price that *drops* between quote
and checkout is refused, because the buyer authorised specific terms. That is a
policy choice, reversible in one line, and it is reported rather than tuned away —
a false-refusal rate of exactly zero would say more about the corpus than the
gateway.

---

## 4. Workflow: one purchase, end to end

```
1. Human delegates   → Authority{ ₹1500, {outdoor,kitchen,books}, +24h }
                       signed Ed25519 → assistant key
2. Agent decides     → LLM picks SKU + quantity via tools
                       (no price parameter exists — it cannot propose one)
3. Intent built      → items priced FROM THE CATALOG, signed by the leaf key
4. Gateway decides   → idempotency claim (winner executes, losers replay)
                       merchant → chain (8 checks) → intent signature → nonce
                       → capability → catalog recompute → category → budget → stock
                       ~18 recorded steps, sub-millisecond, no LLM
5. On ALLOW only     → Razorpay test-mode order created
6. Always            → hash-chained ledger entry (incl. "no_call" on refusals)
7. Always            → trace events streamed over SSE to the console
```

An attack diverges at step 4 and never reaches 5.

---

## 5. How to make it stand out further

Ordered by evidence-per-hour, honestly assessed.

### Done since the first draft of this section

**1. Property-based fuzzing over mandates (Hypothesis).** ✅ Built
(`tests/test_fuzz_invariant.py`). 1,500 generated chains against *"no ALLOW ever
exceeds the human root's grant"* — held, no counterexample. Changed the claim from
"I tested 16 attacks" to "a property over thousands of generated inputs."

**2. Sign the ledger entries.** ✅ Built (`tests/test_signed_ledger.py`). Every
entry signed with the gateway key; a full forward-rewrite that stays hash-consistent
is still caught by the signature. Bar raised from "DB write" to "key compromise".

**3. Multi-process concurrency proof.** ✅ Built
(`tests/test_multiprocess_concurrency.py`). Independent OS processes race the same
idempotency key; exactly one wins. The `UNIQUE` constraint is the serialisation
point across processes, not just threads — the GIL objection is retired.

### Still worth doing

**4. A second red-team run with a stronger model, and publish the transcript.**
The current run is 8 probes with 0 confirmed findings — the README says so. A
longer run either finds something real or makes "tried hard, found nothing"
credible.

**5. Revocation propagation.** Revocation is checked against a set supplied per
request; there is no distribution mechanism or grace window. The interesting
version is the root-key-compromise story: what happens to in-flight mandates the
moment a human's key is revoked.

**6. A latency budget.** The pipeline records per-step microseconds but nothing
aggregates them. "p99 authorization latency under N concurrent agents" is the
number a payments engineer will actually ask for, and the data is already being
collected.

### Deliberately not doing

- **Merkle Mountain Range ledger / public anchoring.** Correct at scale, scope
  creep here, and an external dependency makes the demo fragile.
- **Multi-tenant namespacing.** Real, and correctly a limit rather than a feature.
- **An LLM anywhere near the money path.** The entire thesis.
