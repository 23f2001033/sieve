"""Publish the console to a free Hugging Face *static* Space.

A static Space is free (Docker Spaces now need PRO), so this hosts the console as
a second, redundant live link alongside the Render deployment. The console
defaults its API to the Render gateway, so the HF page is fully live — click an
attack and it runs against the real backend cross-origin.

Two HF-specific quirks this handles, both learned the hard way (engineering log
2026-09-03):

  1. HF injects a `window.huggingface` <script> into the served HTML. A bare
     HTML fragment confuses that injector and it corrupts the inline script, so
     the console is wrapped in a proper <head>/<body> document here — giving the
     injector a clean target — even though the same bare file serves fine from
     FastAPI, which injects nothing.
  2. The injector counted multi-byte box-drawing comment characters wrong, so
     those were removed from ui/console.html at the source.

Run after `hf auth login`.  Usage:  python scripts/deploy_hf_static.py [name]
"""

from __future__ import annotations

import sys
from pathlib import Path

from huggingface_hub import HfApi, whoami

ROOT = Path(__file__).resolve().parent.parent

SPACE_README = """---
title: SIEVE Console
emoji: 🛡️
colorFrom: indigo
colorTo: blue
sdk: static
pinned: false
short_description: Prove an AI storefront cannot be robbed
---

# SIEVE — the glass-box console

A storefront an AI agent can shop from, that proves live it cannot be robbed by a
hostile AI agent. Razorpay AI Buildathon, Track 01.

This page is live: it drives the real gateway. Click any attack to watch the real
verification pipeline decide, run the whole corpus, run the buyer or red-team
agent. If the gateway is briefly unreachable it falls back to a recorded run and
says so — it never fakes being connected.
"""


def wrap(fragment: str) -> str:
    """Give HF's script injector a real <head>/<body> to target."""
    marker = '<div id="root"></div>'
    head, _, body = fragment.partition(marker)
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n'
        + head.strip()
        + '\n</head>\n<body>\n'
        + marker + '\n' + body.strip()
        + '\n</body>\n</html>\n'
    )


def main() -> int:
    try:
        user = whoami()["name"]
    except Exception:
        print("Not logged in. Run:  hf auth login")
        return 1

    name = sys.argv[1] if len(sys.argv) > 1 else "sieve-console"
    repo_id = f"{user}/{name}"
    api = HfApi()
    api.create_repo(repo_id=repo_id, repo_type="space", space_sdk="static", exist_ok=True)

    wrapped = wrap((ROOT / "ui" / "console.html").read_text(encoding="utf-8"))
    tmp_index = ROOT / "_hf_index.html"
    tmp_readme = ROOT / "_hf_README.md"
    tmp_index.write_text(wrapped, encoding="utf-8")
    tmp_readme.write_text(SPACE_README, encoding="utf-8")
    try:
        api.upload_file(path_or_fileobj=str(tmp_readme), path_in_repo="README.md",
                        repo_id=repo_id, repo_type="space")
        api.upload_file(path_or_fileobj=str(tmp_index), path_in_repo="index.html",
                        repo_id=repo_id, repo_type="space")
    finally:
        tmp_index.unlink(missing_ok=True)
        tmp_readme.unlink(missing_ok=True)

    print(f"Live: https://{user}-{name}.static.hf.space".lower())
    print(f"Page: https://huggingface.co/spaces/{repo_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
