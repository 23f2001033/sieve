"""Razorpay test-mode payment rail.

The rail is deliberately reached at exactly one point: **after** the policy engine
has returned ALLOW. A refused intent never produces a Razorpay call at all, which
is what makes "bounded and gated" a property of the code rather than a claim in a
README — the audit trail shows `razorpay: no call made` on every refusal.

Test mode moves no real money. Orders created here are real API objects on a real
Razorpay account; they are simply not settled.

Degradation is explicit and recorded. With no credentials the rail reports
`configured=False` and every authorisation is stamped `stub` in the ledger, so a
reader can tell at a glance which runs touched the real API and which did not.
Silently pretending would defeat the point of the audit trail.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

from sieve.config import load_env

API_ROOT = "https://api.razorpay.com/v1"


@dataclass(frozen=True, slots=True)
class OrderResult:
    """What the rail did, always recorded — including when it did nothing."""

    status: str          # "created" | "stub" | "error"
    order_id: str | None
    amount_paise: int
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"status": self.status, "order_id": self.order_id,
                "amount_paise": self.amount_paise, "detail": self.detail}


class RazorpayTestMode:
    def __init__(self, *, key_id: str | None = None, key_secret: str | None = None,
                 timeout: float = 20.0) -> None:
        try:
            load_env()
        except Exception:
            pass
        self.key_id = key_id if key_id is not None else os.environ.get("RAZORPAY_KEY_ID", "")
        self.key_secret = (key_secret if key_secret is not None
                           else os.environ.get("RAZORPAY_KEY_SECRET", ""))
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.key_id and self.key_secret)

    @property
    def is_test_mode(self) -> bool:
        """Refuse to run against a live key. This project creates orders
        automatically from an autonomous agent's decisions; doing that against a
        production key would move real money."""
        return self.key_id.startswith("rzp_test_")

    def create_order(self, *, amount_paise: int, receipt: str,
                     notes: dict[str, str] | None = None) -> OrderResult:
        if not self.configured:
            return OrderResult("stub", None, amount_paise,
                               "no Razorpay credentials configured")
        if not self.is_test_mode:
            # A hard stop, not a warning. An agent-driven system must never be
            # pointed at a live key by accident.
            return OrderResult("error", None, amount_paise,
                               "refusing to use a non-test key (expected rzp_test_ prefix)")
        try:
            r = httpx.post(
                f"{API_ROOT}/orders",
                auth=(self.key_id, self.key_secret),
                json={"amount": amount_paise, "currency": "INR",
                      "receipt": receipt[:40], "notes": notes or {}},
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            return OrderResult("error", None, amount_paise, f"transport error: {exc}")

        if r.status_code >= 400:
            return OrderResult("error", None, amount_paise,
                               f"{r.status_code}: {r.text[:200]}")
        body = r.json()
        return OrderResult("created", body.get("id"), body.get("amount", amount_paise),
                           f"status={body.get('status')}")


class NullRail:
    """Used when the rail is deliberately absent — tests, and the corpus runs.
    Records that no call was made rather than skipping the record."""

    configured = False
    is_test_mode = True

    def create_order(self, *, amount_paise: int, receipt: str,
                     notes: dict[str, str] | None = None) -> OrderResult:
        return OrderResult("stub", None, amount_paise, "payment rail disabled")
