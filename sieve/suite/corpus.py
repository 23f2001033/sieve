"""The corpus abstractions: attacks, benign cases, and their results.

The design rule that makes this evidence rather than a demo: **every case
declares its expected outcome before any gateway runs.** An attack says "this
must be refused" (ideally naming the reason); a benign case says "this must be
allowed." The runner compares the gateway's actual verdict against that
declaration. The gateway is never consulted about what *should* happen — only
about what does.

Two things are recorded per attack, and they are not the same:

  - **contained**: did the gateway refuse the malicious money action? This is
    the headline security metric. A contained attack is one where money did not
    move (or moved only as the legitimate baseline allows).
  - **reason_expected**: did it refuse for the reason the attack targets? A
    mismatch does not mean money moved — it means the attack was stopped by a
    different check than intended, which is worth investigating because the
    attack may not be exercising what its author believed. Surfaced, not hidden.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sieve.contracts.adapter import GatewayAdapter
from sieve.contracts.verdict import ReasonCode, Verdict
from sieve.suite.world import World


@dataclass(frozen=True, slots=True)
class AttackResult:
    attack_id: str
    family: str
    name: str
    contained: bool
    reason_expected: bool
    actual_reason: str
    detail: str

    def to_json(self) -> dict:
        return {
            "attack_id": self.attack_id,
            "family": self.family,
            "name": self.name,
            "contained": self.contained,
            "reason_expected": self.reason_expected,
            "actual_reason": self.actual_reason,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class BenignResult:
    case_id: str
    name: str
    allowed: bool  # True is correct; False is a FALSE REFUSAL
    actual_reason: str

    @property
    def false_refusal(self) -> bool:
        return not self.allowed

    def to_json(self) -> dict:
        return {
            "case_id": self.case_id,
            "name": self.name,
            "allowed": self.allowed,
            "false_refusal": self.false_refusal,
            "actual_reason": self.actual_reason,
        }


class Attack:
    """Base class for a single attack.

    Subclasses set the class-level metadata and implement `perform`, which builds
    and submits whatever malicious request the attack represents and returns the
    verdict that decides containment. Overriding `run` directly is allowed for
    attacks that need multiple or concurrent submissions (replay, aggregate
    budget, double-spend).
    """

    attack_id: str = ""
    family: str = ""
    name: str = ""
    # The reason codes that count as "refused for the right reason". An attack is
    # contained if the verdict is refused at all; this set is the finer check.
    expected_reasons: frozenset[ReasonCode] = frozenset()

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        raise NotImplementedError

    def run(self, adapter: GatewayAdapter, world: World) -> AttackResult:
        verdict = self.perform(adapter, world)
        return self._result(verdict)

    def _result(self, verdict: Verdict, *, detail: str = "") -> AttackResult:
        contained = verdict.refused
        reason_expected = (
            not self.expected_reasons or verdict.reason_code in self.expected_reasons
        )
        return AttackResult(
            attack_id=self.attack_id,
            family=self.family,
            name=self.name,
            contained=contained,
            reason_expected=reason_expected and contained,
            actual_reason=verdict.reason_code.value,
            detail=detail or verdict.explanation,
        )


class BenignCase:
    """Base class for a legitimate transaction that MUST be allowed. A refusal
    here is a false refusal, the other half of the honesty metric."""

    case_id: str = ""
    name: str = ""

    def perform(self, adapter: GatewayAdapter, world: World) -> Verdict:
        raise NotImplementedError

    def run(self, adapter: GatewayAdapter, world: World) -> BenignResult:
        verdict = self.perform(adapter, world)
        return BenignResult(
            case_id=self.case_id,
            name=self.name,
            allowed=verdict.allowed,
            actual_reason=verdict.reason_code.value,
        )
