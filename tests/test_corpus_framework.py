"""Prove the corpus framework runs and the differential is real.

Not asserting exact numbers yet (the full corpus isn't written), but asserting
the shape holds: attacks run against both gateways, SIEVE contains what it should,
and the naive gateway is genuinely weaker on at least one attack — otherwise the
differential proves nothing.
"""

from __future__ import annotations

from sieve.suite.attacks.authorization import AUTHORIZATION_ATTACKS
from sieve.suite.runner import run_corpus


def test_authorization_family_runs_against_both_targets():
    report = run_corpus(AUTHORIZATION_ATTACKS, [])

    assert set(report.target_names) == {"SIEVE (reference)", "Naive (amount cap + confirm)"}
    assert len(report.attack_matrix) == len(AUTHORIZATION_ATTACKS)

    # Every attack produced a result for every target.
    for row in report.attack_matrix.values():
        assert set(row.keys()) == set(report.target_names)


def test_sieve_contains_the_whole_authorization_family():
    report = run_corpus(AUTHORIZATION_ATTACKS, [])
    sieve = report.summary("SIEVE (reference)")
    assert sieve.contained == sieve.attacks_total, (
        "SIEVE should contain every authorization-integrity attack; "
        f"contained {sieve.contained}/{sieve.attacks_total}"
    )


def test_naive_gateway_is_genuinely_weaker():
    """The differential must be real: the naive gateway has to let at least one
    attack through that SIEVE contains, or the comparison is meaningless."""
    report = run_corpus(AUTHORIZATION_ATTACKS, [])
    naive = report.summary("Naive (amount cap + confirm)")
    sieve = report.summary("SIEVE (reference)")
    assert naive.contained < sieve.contained, (
        f"naive contained {naive.contained}, SIEVE {sieve.contained} — "
        "the naive baseline is supposed to be weaker"
    )


def test_reason_codes_are_the_expected_ones():
    """Containment for the right reason. A mismatch here means an attack was
    stopped by a different check than it targets — worth knowing."""
    report = run_corpus(AUTHORIZATION_ATTACKS, [])
    for attack_id, row in report.attack_matrix.items():
        result = row["SIEVE (reference)"]
        assert result.reason_expected, (
            f"{attack_id} contained by SIEVE but via {result.actual_reason}, "
            "not the reason the attack targets"
        )
