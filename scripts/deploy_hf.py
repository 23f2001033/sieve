"""Deploy the SIEVE gateway to a Hugging Face Docker Space.

Run AFTER `hf auth login` (the token lands in the local cache; this script reads
it automatically and never sees it in plain text here). It:

  1. creates the Space (docker SDK) if it does not exist,
  2. sets GROQ_* and RAZORPAY_* as Space *secrets*, read from the local .env,
  3. uploads only what the container needs — code, UI, Dockerfile, a
     Space-flavoured README — never .env, tests, or working notes.

Usage:  python scripts/deploy_hf.py [space_name]
"""

from __future__ import annotations

import sys
from pathlib import Path

from huggingface_hub import HfApi, whoami

from sieve.config import load_env
import os

ROOT = Path(__file__).resolve().parent.parent

SPACE_README = """---
title: SIEVE Console
emoji: 🛡️
colorFrom: indigo
colorTo: blue
sdk: docker
app_port: 7860
pinned: false
short_description: A storefront AI agents can shop from that proves it can't be robbed
---

# SIEVE

A storefront an AI agent can shop from — that proves, live, it cannot be robbed
by a hostile AI agent. Razorpay AI Buildathon, Track 01.

This Space runs the real gateway. Open it and the console is fully live: click any
attack to watch the real verification pipeline decide, run the whole corpus, run
the buyer or red-team agent, toggle the ledger tamper check. Source and the full
write-up: see the linked GitHub repository.

Single-instance by design — every correctness guarantee assumes one process
against one disk. See docs/LIMITS.md in the repo.
"""

# Exactly what the container needs. Everything else — .env, tests, _internal,
# the venv, working notes — is deliberately excluded.
INCLUDE = ["sieve", "ui", "scripts/sync_ui.py", "scripts/reproduce.py",
           "pyproject.toml", "Dockerfile", "docs"]

SECRET_KEYS = ["GROQ_API_KEY", "GROQ_BASE_URL", "GROQ_MODEL",
               "RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET"]


def main() -> int:
    load_env()
    api = HfApi()
    try:
        user = whoami()["name"]
    except Exception:
        print("Not logged in. Run:  hf auth login   (needs a WRITE token)")
        return 1

    name = sys.argv[1] if len(sys.argv) > 1 else "sieve-console"
    repo_id = f"{user}/{name}"
    print(f"Deploying to Space: {repo_id}")

    api.create_repo(repo_id=repo_id, repo_type="space", space_sdk="docker",
                    exist_ok=True)

    # README carries the Space config header; upload it as the Space's README.
    (ROOT / "_hf_README.md").write_text(SPACE_README, encoding="utf-8")
    api.upload_file(path_or_fileobj=str(ROOT / "_hf_README.md"),
                    path_in_repo="README.md", repo_id=repo_id, repo_type="space")
    (ROOT / "_hf_README.md").unlink()

    for rel in INCLUDE:
        path = ROOT / rel
        if path.is_dir():
            api.upload_folder(folder_path=str(path), path_in_repo=rel,
                              repo_id=repo_id, repo_type="space",
                              ignore_patterns=["__pycache__", "*.pyc", "*.db*"])
        else:
            api.upload_file(path_or_fileobj=str(path), path_in_repo=rel,
                            repo_id=repo_id, repo_type="space")
        print(f"  uploaded {rel}")

    for key in SECRET_KEYS:
        value = os.environ.get(key, "")
        if value:
            api.add_space_secret(repo_id=repo_id, key=key, value=value)
            print(f"  secret set: {key}")
        else:
            print(f"  secret MISSING (skipped): {key}")

    url = f"https://huggingface.co/spaces/{repo_id}"
    print(f"\nDone. Building now — first build takes a few minutes.\n{url}")
    print(f"Live URL: https://{user}-{name}.hf.space".lower())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
