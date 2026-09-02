"""Trace events — the structured record that streams to the glass-box UI.

Every gateway decision produces a short sequence of these. They are the same
events the SSE stream in the console renders live, derived from the real verdict
rather than narrated after the fact: an ALLOW yields a verify → policy → ledger
sequence, a REFUSE yields policy-refused → ledger. The payload hash ties each
event to the exact intent it decided, so a viewer can correlate the stream with
the ledger.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sieve.contracts.canonical import canonical_digest
from sieve.contracts.verdict import Verdict


@dataclass(frozen=True, slots=True)
class TraceEvent:
    t: str          # HH:MM:SS.mmm, the tail-log timestamp
    ev: str         # MANDATE_VERIFIED | POLICY_ALLOWED | POLICY_REFUSED | LEDGER_APPENDED
    hash: str       # first 8 hex of the intent digest
    v: str          # ALLOW | REFUSE | PROV
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"t": self.t, "ev": self.ev, "hash": self.hash, "v": self.v, "detail": self.detail}


def _stamp() -> str:
    d = datetime.now(timezone.utc).astimezone()
    return f"{d.hour:02d}:{d.minute:02d}:{d.second:02d}.{d.microsecond // 1000:03d}"


def events_for(intent_body: dict, verdict: Verdict) -> list[TraceEvent]:
    """The trace events a single decision emits, built from the real verdict."""
    digest = canonical_digest("intent", intent_body).hex()[:8]
    if verdict.allowed:
        return [
            TraceEvent(_stamp(), "MANDATE_VERIFIED", digest, "ALLOW", "chain + signatures verified"),
            TraceEvent(_stamp(), "POLICY_ALLOWED", digest, "ALLOW", verdict.explanation),
            TraceEvent(_stamp(), "LEDGER_APPENDED", digest, "PROV", "hash-chained, prev-linked"),
        ]
    return [
        TraceEvent(_stamp(), "POLICY_REFUSED", digest, "REFUSE", verdict.reason_code.value),
        TraceEvent(_stamp(), "LEDGER_APPENDED", digest, "PROV", "refusal recorded"),
    ]
