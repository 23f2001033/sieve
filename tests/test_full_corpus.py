"""The full 16-attack corpus against both gateways.

The single test that most directly backs the README's headline numbers. It runs
every attack against SIEVE and the naive baseline and asserts the properties the
submission claims: SIEVE contains all 16, each for the reason its attack targets,
and the naive baseline is strictly and substantially weaker.
"""

from __future__ import annotations

from sieve.suite.attacks import ALL_ATTACKS
from sieve.suite.runner import run_corpus


def test_corpus_has_sixteen_distinct_attacks():
    ids = [a.attack_id for a in ALL_ATTACKS]
    assert len(ids) == 16
    assert len(set(ids)) == 16, "attack ids must be unique"


def test_sieve_contains_every_attack():
    report = run_corpus(ALL_ATTACKS, [])
    s = report.summary("SIEVE (reference)")
    misses = [aid for aid, row in report.attack_matrix.items()
              if not row["SIEVE (reference)"].contained]
    assert s.contained == 16, f"SIEVE let through: {misses}"


def test_sieve_contains_each_for_the_targeted_reason():
    """Containment for the right reason, across the whole corpus. A refusal via
    the wrong check would mean the attack isn't exercising what it claims to."""
    report = run_corpus(ALL_ATTACKS, [])
    wrong = [
        (aid, row["SIEVE (reference)"].actual_reason)
        for aid, row in report.attack_matrix.items()
        if not row["SIEVE (reference)"].reason_expected
    ]
    assert not wrong, f"contained via an unexpected reason: {wrong}"


def test_naive_is_strictly_and_substantially_weaker():
    report = run_corpus(ALL_ATTACKS, [])
    naive = report.summary("Naive (amount cap + confirm)")
    sieve = report.summary("SIEVE (reference)")
    assert naive.contained < sieve.contained
    # The naive design should fail a clear majority — the gap is the point.
    assert naive.contained <= 6, (
        f"naive contained {naive.contained}/16 — expected it to fail most attacks"
    )


def test_naive_lets_through_the_delegation_family():
    """The delegation-chain attacks (B) are the ones the naive design structurally
    cannot see, since it inspects only the leaf mandate."""
    report = run_corpus(ALL_ATTACKS, [])
    for aid in ("B5", "B6", "B7", "B8"):
        assert not report.attack_matrix[aid]["Naive (amount cap + confirm)"].contained, (
            f"{aid} should slip past the naive gateway"
        )
