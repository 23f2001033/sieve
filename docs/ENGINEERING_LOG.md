# Engineering Log

Dated, as it happened. Wrong turns and withdrawn numbers included — a log that
only records successes is not a log, it is marketing.

---

## 2026-09-02

### Setup

Repo initialised. Python 3.11.9 locally, so the project targets 3.11+ rather
than the 3.12 originally sketched; nothing in the design needs 3.12.

Order of construction is deliberate: `contracts/` before `gateway/`. The
mandate schema, canonical encoding, verdict type and adapter protocol are the
architectural spine, and changing a signing format after signatures exist is
expensive. Spine first, implementation second.

### #1 — The verifier was right and my test was wrong, but the ergonomics were the real bug

**Symptom.** `test_valid_two_hop_chain_is_accepted` failed on what should have
been the most boring path in the system: an honest two-hop chain, correctly
signed, no attack anywhere. The refusal read:

```
expiry extended: child expires 2026-09-03T14:05:15.764550+00:00,
                 parent expires 2026-09-03T14:05:15.423675+00:00
```

341 microseconds.

**Diagnosis.** My test helper derived each expiry from its own `utc_now()` call.
The parent was built first, the child a fraction of a millisecond later, and
both asked for "24 hours from now" — so the child's window ended *after* the
parent's. The monotonic narrowing invariant says a child may not outlive its
parent, so the verifier refused it. Correctly.

The first instinct was to loosen the check — add a tolerance window, compare at
second granularity. That instinct was wrong, and worth recording because it is
the exact shape of how security properties get quietly dismantled. A tolerance
on expiry comparison is an attacker-controllable margin: it would have made the
headline invariant negotiable in order to fix a test.

**What was actually wrong.** Not the verifier — the ergonomics around it. The
obvious way for honest code to say "delegate for 24 hours" produces an invalid
chain, and nothing warns you. Any real integrator would hit this within an hour
and would probably reach for the same bad fix I did.

**Fix.** Two parts, and the split matters:

1. The verifier stays exactly as strict as it was. Not touched.
2. Added `Authority.narrowed()`, which clamps every requested dimension against
   the parent's ceiling — amount, categories, capabilities, expiry. An honest
   issuer now cannot accidentally produce a widened chain, because the safe
   construction is also the convenient one. Asking for more than you hold
   silently clamps down rather than raising, since callers routinely say "give
   it ₹500" without knowing their own ceiling.

Test helper switched to a single module-level base instant.

**What this changed in my thinking.** The narrowing invariant is not just a
check to pass; it is a constraint the *issuing* API has to help callers honour.
A rule that is easy to violate by accident will be violated by accident, and
then someone will relax the rule. Three new tests now pin the clamp, including
one asserting that clamping did not quietly become "inherit everything".

### #2 — A test with teeth caught a cosmetic bug that was actually a spec violation

`test_refusal_explanation_is_human_readable` asserts that every refusal ends in
a full stop and runs to at least six words. It failed: the
`AUTHORITY_WIDENED` explanation was being assembled by interpolating a raw
violation string and never terminated.

Trivial to fix. Worth logging because the test exists at all. The project's
claim is that every money decision is *explainable*, and "Denied" — or a
half-formed sentence fragment — does not meet that bar. Asserting the shape of
the explanation is how the claim stays true under time pressure at 2am, rather
than being the first thing that quietly degrades.

### Status at end of session

- `contracts/canonical.py` — canonical binary encoding. Signing happens over
  this, never over JSON, which removes the entire canonicalisation-confusion
  attack class at the root rather than defending against it case by case.
  Verified injective on adversarial pairs: key reordering, `"1"` vs `1`,
  `True` vs `1`, NFC/NFD unicode, and concatenation ambiguity (`{"ab":"c"}` vs
  `{"a":"bc"}`). Floats and out-of-range integers are refused at the encoder —
  money is integer paise, and an amount that would overflow is rejected before
  it can wrap somewhere downstream.
- `contracts/mandate.py` — Authority, Delegation, LineItem, Intent. "Unrestricted"
  is deliberately not representable: categories and capabilities are always
  explicit frozensets, so unlimited authority cannot be constructed by accident.
- `contracts/verdict.py` — verdicts carry the full ordered check trail, passing
  steps included. A pipeline that only records failures cannot prove it ran the
  check that mattered.
- `gateway/crypto.py` — Ed25519 and `verify_delegation_chain`. Check order is a
  security property in itself: depth bound, then structural checks, then
  revocation and expiry, and only then signature verification, so a forged
  chain cannot make us do expensive cryptography before we reject it.
- 21 tests passing, written as attacks rather than happy paths. Each asserts the
  *specific* refusal reason, not merely that something was refused — a verifier
  that says no for the wrong reason is indistinguishable from a broken one under
  a test suite that only checks `allowed is False`.

**Not yet verified:** what Razorpay test mode actually exposes. Assumed nothing;
checking before anything depends on it.
