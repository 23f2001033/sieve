"""The benign corpus — the other half of the honesty metric.

Containment is meaningless without this: a gateway that refuses everything
contains every attack. These tests pin the false-refusal behaviour of both
gateways, including the project's strongest single finding — that the naive
design is not merely less secure but also *far worse for real customers*.
"""

from __future__ import annotations

from sieve.suite.benign.cases import benign_corpus
from sieve.suite.runner import run_corpus

SIEVE = "SIEVE (reference)"
NAIVE = "Naive (amount cap + confirm)"


def test_sieve_allows_the_overwhelming_majority_of_legitimate_traffic():
    report = run_corpus([], benign_corpus(120, seed=42))
    s = report.summary(SIEVE)
    rate = s.false_refusals / s.benign_total
    assert rate < 0.03, f"SIEVE false-refusal rate {rate:.1%} is too high"


def test_sieve_false_refusals_come_only_from_the_documented_policy():
    """Every SIEVE false refusal must be the known, deliberate one (favourable
    price drop). An unexplained false refusal is a bug, not a policy."""
    report = run_corpus([], benign_corpus(120, seed=42))
    unexplained = [
        (cid, row[SIEVE].actual_reason)
        for cid, row in report.benign_matrix.items()
        if row[SIEVE].false_refusal and not cid.startswith("BN-drop")
    ]
    assert not unexplained, f"unexplained SIEVE false refusals: {unexplained}"


def test_sieve_allows_the_honest_retry():
    """The case that separates a real implementation from a demo: a client that
    times out and retries must get its original result, not a refusal."""
    report = run_corpus([], benign_corpus(120, seed=42))
    retries = [row[SIEVE] for cid, row in report.benign_matrix.items()
               if cid.startswith("BN-retry")]
    assert retries, "the corpus must exercise honest retries"
    assert all(r.allowed for r in retries), "SIEVE refused an honest retry"


def test_naive_refuses_honest_retries_and_that_is_the_headline():
    """The naive design conflates a replay attack with a legitimate retry, so it
    blocks real customers. This is the finding that inverts the assumed
    security-versus-convenience tradeoff."""
    report = run_corpus([], benign_corpus(120, seed=42))
    retries = [row[NAIVE] for cid, row in report.benign_matrix.items()
               if cid.startswith("BN-retry")]
    assert retries
    assert all(not r.allowed for r in retries), (
        "expected the naive gateway to refuse honest retries"
    )
    assert all(r.actual_reason == "nonce_replayed" for r in retries)


def test_sieve_is_both_safer_and_kinder_than_naive():
    """The two metrics together. Neither alone is a claim worth making."""
    from sieve.suite.attacks import ALL_ATTACKS

    report = run_corpus(ALL_ATTACKS, benign_corpus(200, seed=42))
    s, n = report.summary(SIEVE), report.summary(NAIVE)
    assert s.contained > n.contained, "SIEVE should contain strictly more attacks"
    assert s.false_refusals < n.false_refusals, (
        "SIEVE should also wrongly refuse strictly fewer legitimate customers"
    )
