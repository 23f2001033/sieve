"""Verdicts and the check steps that produce them.

A verdict is never a bare boolean. It carries the full ordered sequence of
checks that ran, what each compared, and why each passed or failed. That is not
decoration: it is the mechanism behind this project's governing principle —
*no claim appears in the README without a button in the app that demonstrates
it*. The UI's live verification pipeline renders exactly this structure, so the
evidence a judge watches on screen is the same evidence the policy engine acted
on, not a re-narration of it.

Two consequences worth naming:

  - Every refusal must name a `ReasonCode` and explain itself in a sentence a
    merchant could read. "Denied" is not an acceptable output for a system whose
    entire claim is that money decisions are explainable.
  - Steps are recorded even when they pass. A pipeline that only reports
    failures cannot prove it actually ran the check that mattered.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ReasonCode(str, Enum):
    """Why a request was allowed or refused.

    Grouped by the stage that produces them, which is also the order the
    pipeline runs in — cheapest and most fundamental checks first, so an
    attacker cannot make us do expensive work before we reject them.
    """

    ALLOWED = "allowed"

    # Cryptographic integrity — attack family A
    SIGNATURE_INVALID = "signature_invalid"
    INTENT_SIGNER_MISMATCH = "intent_signer_mismatch"
    MALFORMED = "malformed"

    # Delegation chain — attack family B
    CHAIN_ROOT_UNKNOWN = "chain_root_unknown"
    CHAIN_BROKEN = "chain_broken"
    AUTHORITY_WIDENED = "authority_widened"
    LINK_EXPIRED = "link_expired"
    KEY_REVOKED = "key_revoked"

    # Replay and idempotency — attack families A and C
    NONCE_REPLAYED = "nonce_replayed"
    INTENT_EXPIRED = "intent_expired"

    # Budget, scope, inventory — attack family C
    AMOUNT_EXCEEDS_AUTHORITY = "amount_exceeds_authority"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CATEGORY_NOT_PERMITTED = "category_not_permitted"
    CAPABILITY_MISSING = "capability_missing"
    MERCHANT_MISMATCH = "merchant_mismatch"
    OUT_OF_STOCK = "out_of_stock"

    # Data plane and numerics — attack family D
    TOTAL_MISMATCH = "total_mismatch"
    PRICE_CHANGED = "price_changed"
    REFUND_EXCEEDS_CAPTURE = "refund_exceeds_capture"

    # Internal
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True, slots=True)
class CheckStep:
    """One check in the verification pipeline, with its evidence.

    `evidence` holds what was actually compared — the claimed value against the
    permitted one — so a reviewer can confirm the decision rather than take it
    on trust.
    """

    name: str
    passed: bool
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    duration_us: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
            "evidence": _jsonable(self.evidence),
            "duration_us": self.duration_us,
        }


@dataclass(frozen=True, slots=True)
class Verdict:
    allowed: bool
    reason_code: ReasonCode
    explanation: str
    steps: tuple[CheckStep, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def refused(self) -> bool:
        return not self.allowed

    @property
    def failed_step(self) -> CheckStep | None:
        """The first check that failed, if any. What the UI highlights."""
        for step in self.steps:
            if not step.passed:
                return step
        return None

    def to_json(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code.value,
            "explanation": self.explanation,
            "steps": [step.to_json() for step in self.steps],
            "evidence": _jsonable(self.evidence),
        }


class StepRecorder:
    """Accumulates check steps and times each one.

    Used by the policy engine so that recording evidence is the path of least
    resistance rather than an extra chore that gets skipped under time pressure.
    """

    def __init__(self) -> None:
        self._steps: list[CheckStep] = []
        self._started = time.perf_counter_ns()

    def record(
        self,
        name: str,
        passed: bool,
        detail: str,
        evidence: dict[str, Any] | None = None,
    ) -> bool:
        now = time.perf_counter_ns()
        self._steps.append(
            CheckStep(
                name=name,
                passed=passed,
                detail=detail,
                evidence=evidence or {},
                duration_us=(now - self._started) // 1000,
            )
        )
        self._started = now
        return passed

    @property
    def steps(self) -> tuple[CheckStep, ...]:
        return tuple(self._steps)

    def allow(self, explanation: str, evidence: dict[str, Any] | None = None) -> Verdict:
        return Verdict(
            allowed=True,
            reason_code=ReasonCode.ALLOWED,
            explanation=explanation,
            steps=self.steps,
            evidence=evidence or {},
        )

    def refuse(
        self,
        reason_code: ReasonCode,
        explanation: str,
        evidence: dict[str, Any] | None = None,
    ) -> Verdict:
        return Verdict(
            allowed=False,
            reason_code=reason_code,
            explanation=explanation,
            steps=self.steps,
            evidence=evidence or {},
        )


def _jsonable(value: Any) -> Any:
    """Make evidence JSON-serialisable without losing information.

    Sets become sorted lists and bytes become hex, both deterministically, so
    the same evidence always renders the same way in the UI and in RESULTS.md.
    """
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_jsonable(item) for item in value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, Enum):
        return value.value
    return value
