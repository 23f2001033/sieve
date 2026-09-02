"""LLM client — the ONLY place a language model is reachable from.

This module lives in `sieve/agents/` deliberately. `tests/test_no_llm_in_policy.py`
lists `sieve.agents` as a forbidden import for every module on the money path, so
the build fails if the policy engine ever gains a route to this file. The
boundary is mechanical, not a convention.

A thin httpx wrapper over an OpenAI-compatible `/chat/completions` with tool
calling. No model SDK is vendored — one less dependency, and it keeps the
forbidden-import list short and legible. Defaults to Groq; any
OpenAI-compatible endpoint works by setting the base URL.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx

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


class LLMUnavailable(RuntimeError):
    """No key configured, or the provider refused. Callers degrade rather than
    crash — the gateway does not depend on the model being reachable."""


class LLMClient:
    """Provider-agnostic OpenAI-compatible chat client.

    Deliberately not named after one vendor. Groq (`gsk_…` keys,
    api.groq.com) and xAI's Grok (`xai-…` keys, api.x.ai) are different
    services with near-identical names, and pointing one's key at the other's
    endpoint fails with a misleading "model not found" — see ENGINEERING_LOG
    2026-09-03. Both env spellings are accepted so either works.
    """

    def __init__(self, *, api_key: str | None = None, base_url: str | None = None,
                 model: str | None = None, timeout: float = 45.0) -> None:
        load_env()
        # `None` means "not supplied — look it up". An explicitly passed value,
        # including an empty string, wins outright: a caller saying "no key" must
        # not silently inherit one from the environment.
        self.api_key = api_key if api_key is not None else (
            os.environ.get("GROQ_API_KEY") or os.environ.get("GROK_API_KEY") or "")
        self.base_url = (base_url if base_url is not None else (
            os.environ.get("GROQ_BASE_URL") or os.environ.get("GROK_BASE_URL")
            or "https://api.groq.com/openai/v1")).rstrip("/")
        self.model = model if model is not None else (
            os.environ.get("GROQ_MODEL") or os.environ.get("GROK_MODEL")
            or "openai/gpt-oss-120b")
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict] | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        """One completion. Returns the assistant message dict (which may carry
        `tool_calls`). Raises LLMUnavailable on any transport or auth failure."""
        if not self.configured:
            raise LLMUnavailable("GROK_API_KEY is not set")

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        # A 429 is a wait, not a failure. Providers publish a per-minute token
        # budget and tell you how long to pause; treating that as fatal would
        # abandon a run for a few seconds of patience.
        import re
        import time

        last_error = ""
        for attempt in range(4):
            try:
                r = httpx.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}",
                             "Content-Type": "application/json"},
                    json=payload,
                    timeout=self.timeout,
                )
            except httpx.HTTPError as exc:
                raise LLMUnavailable(
                    f"transport error talking to {self.base_url}: {exc}") from exc

            if r.status_code == 429 and attempt < 3:
                match = re.search(r"try again in ([\d.]+)s", r.text)
                delay = float(match.group(1)) + 0.5 if match else 2.0 * (attempt + 1)
                time.sleep(min(delay, 30.0))
                last_error = r.text[:200]
                continue
            break

        if r.status_code >= 400:
            hint = " (rate limited after retries)" if r.status_code == 429 else ""
            raise LLMUnavailable(f"{r.status_code} from provider{hint}: {r.text[:300] or last_error}")

        try:
            return r.json()["choices"][0]["message"]
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise LLMUnavailable(f"unexpected response shape: {r.text[:300]}") from exc
# backward-compatible alias
GrokClient = LLMClient
