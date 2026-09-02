"""The build fails if the money-decision path can reach a language model.

This is the mechanical enforcement of the project's central claim. It is easy to
*say* "no LLM touches a money decision"; every competitor says some version of
it. This test makes it a fact about the code that cannot quietly rot: add an
`import anthropic` anywhere under the policy path and CI goes red.

Two things make it more than theatre:

  1. It follows the real import graph transitively from the policy modules, so a
     model client pulled in three hops away is still caught.
  2. `test_the_guard_actually_catches_a_violation` mutation-tests the guard
     itself against a synthetic offending module, so we know it fails for the
     right reason rather than passing vacuously — a guard that never fires is
     indistinguishable from no guard at all.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

# Every module that participates in deciding whether money moves. If a new file
# joins that path, add it here — the omission is the only way to defeat this.
POLICY_MODULES = [
    "sieve/contracts/canonical.py",
    "sieve/contracts/mandate.py",
    "sieve/contracts/verdict.py",
    "sieve/gateway/crypto.py",
    "sieve/gateway/policy.py",
    "sieve/gateway/gateway.py",
    "sieve/gateway/nonce.py",
    "sieve/gateway/idempotency.py",
    "sieve/gateway/ledger.py",
    "sieve/gateway/inventory.py",
    "sieve/gateway/razorpay.py",
    "sieve/config.py",
]

# Model clients and inference libraries. Substring match on the top-level import
# name, so `anthropic`, `anthropic.types`, `openai`, `google.generativeai`,
# `transformers`, `torch` are all caught.
FORBIDDEN_PREFIXES = (
    "anthropic",
    "openai",
    "google.generativeai",
    "google.genai",
    "cohere",
    "mistralai",
    "transformers",
    "torch",
    "llama_cpp",
    "ollama",
    "vllm",
    "litellm",
    "langchain",
    "sieve.agents",  # the LLM buyer and red-teamer live here; policy must not import them
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def imported_names(source: str) -> set[str]:
    """Every module name imported by `source`, via a real AST walk."""
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                names.add(node.module)
    return names


def is_forbidden(name: str) -> bool:
    return any(
        name == prefix or name.startswith(prefix + ".")
        for prefix in FORBIDDEN_PREFIXES
    )


def local_dependencies(names: set[str]) -> list[str]:
    """The subset of imports that are our own modules, as repo-relative paths,
    so the walk can follow them transitively."""
    deps = []
    for name in names:
        if name.startswith("sieve."):
            candidate = REPO_ROOT / (name.replace(".", "/") + ".py")
            if candidate.exists():
                deps.append(str(candidate.relative_to(REPO_ROOT)).replace("\\", "/"))
    return deps


def test_policy_path_imports_no_model_client():
    """Transitively walk the policy path; fail on any forbidden import."""
    seen: set[str] = set()
    queue = list(POLICY_MODULES)
    offences: list[str] = []

    while queue:
        rel = queue.pop()
        if rel in seen:
            continue
        seen.add(rel)

        path = REPO_ROOT / rel
        assert path.exists(), f"policy module listed but missing: {rel}"
        names = imported_names(path.read_text(encoding="utf-8"))

        for name in names:
            if is_forbidden(name):
                offences.append(f"{rel} imports forbidden module {name!r}")

        queue.extend(local_dependencies(names))

    assert not offences, "LLM reachable from the money path:\n" + "\n".join(offences)


def test_the_guard_actually_catches_a_violation(tmp_path):
    """Mutation check: point the same machinery at a module that DOES import a
    model client, and confirm it is flagged. A guard that never fires is worth
    nothing; this proves it fires."""
    offending = tmp_path / "offending.py"
    offending.write_text(
        textwrap.dedent(
            """
            import anthropic
            def decide():
                return anthropic.Anthropic()
            """
        ),
        encoding="utf-8",
    )

    names = imported_names(offending.read_text(encoding="utf-8"))
    flagged = [name for name in names if is_forbidden(name)]

    assert "anthropic" in flagged, "the guard failed to catch a real violation"


def test_guard_does_not_false_positive_on_legitimate_imports():
    """The guard must not flag ordinary crypto/stdlib imports, or it would be
    disabled the first time it cried wolf."""
    legitimate = {
        "cryptography.hazmat.primitives.asymmetric.ed25519",
        "hashlib",
        "datetime",
        "sqlite3",
        "sieve.contracts.mandate",
    }
    assert not [name for name in legitimate if is_forbidden(name)]
