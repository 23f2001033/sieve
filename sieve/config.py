"""Environment loading — neutral ground.

This lives outside both `sieve/agents/` and the money path on purpose. The
payment rail needs credentials from `.env`, and so do the LLM agents; if the rail
reached into `sieve.agents` to get them, the money path would gain a transitive
import route to a model client and `tests/test_no_llm_in_policy.py` would fail —
as it did, on exactly that mistake. A shared dependency both sides may import
keeps the boundary intact without duplicating the loader.
"""

from __future__ import annotations

import os
from pathlib import Path

_ENV_LOADED = False


def load_env(path: str | Path = ".env") -> None:
    """Minimal .env reader. Values already in the environment win, so a real
    deployment can override the file without editing it."""
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    p = Path(path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key and key not in os.environ:
                os.environ[key] = value
    _ENV_LOADED = True
