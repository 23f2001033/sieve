"""Per-IP rate limiting for the public demo.

The gateway is safe to expose in the sense that matters — every endpoint is a
read or a sandboxed demo action against test-mode credentials, and no endpoint
can move real money. But two resources are genuinely exhaustible by a stranger:
the LLM token budget behind the agent endpoints, and the corpus runs, which are
CPU-heavy.

So limits are tiered by what each endpoint actually costs, rather than one blanket
number. In-process token buckets are the right shape here precisely because the
gateway is single-node by design — the same property that makes the idempotency
guarantee hold makes a local limiter sufficient. On a multi-instance deployment
this would have to move to a shared store, and that is noted in LIMITS.md
alongside every other single-node assumption.
"""

from __future__ import annotations

import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# (requests, per_seconds) by path prefix, most specific first. The agent routes
# cost real LLM tokens; the corpus routes cost real CPU; reads are cheap.
TIERS: list[tuple[str, int, int]] = [
    ("/v1/agent/", 5, 300),      # 5 agent runs per 5 minutes
    ("/v1/run-corpus", 10, 300),  # 10 full corpus runs per 5 minutes
    ("/v1/attack/", 60, 60),      # single attacks are quick
    ("/v1/", 240, 60),            # everything else
]


class RateLimiter(BaseHTTPMiddleware):
    def __init__(self, app, enabled: bool = True) -> None:
        super().__init__(app)
        self.enabled = enabled
        self._hits: dict[tuple[str, str], list[float]] = defaultdict(list)

    def _tier(self, path: str) -> tuple[str, int, int] | None:
        for prefix, limit, window in TIERS:
            if path.startswith(prefix):
                return prefix, limit, window
        return None

    async def dispatch(self, request, call_next):
        if not self.enabled:
            return await call_next(request)

        tier = self._tier(request.url.path)
        if tier is None:
            return await call_next(request)

        prefix, limit, window = tier
        # X-Forwarded-For's first entry when behind a proxy; the socket otherwise.
        forwarded = request.headers.get("x-forwarded-for", "")
        client = (forwarded.split(",")[0].strip()
                  or (request.client.host if request.client else "unknown"))

        now = time.monotonic()
        key = (client, prefix)
        recent = [t for t in self._hits[key] if now - t < window]

        if len(recent) >= limit:
            retry_after = int(window - (now - recent[0])) + 1
            self._hits[key] = recent
            return JSONResponse(
                {"error": "rate_limited",
                 "detail": f"{limit} requests per {window}s on {prefix}",
                 "retry_after_seconds": retry_after},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        recent.append(now)
        self._hits[key] = recent
        return await call_next(request)
