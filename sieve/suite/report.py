"""Turn a corpus run into the numbers the README leads with.

Two formats: a Markdown table for RESULTS.md, and a compact dict for the API/UI.
The false-refusal rate carries a Wilson 95% confidence interval, because a raw
percentage on a few hundred cases without an interval overstates its own
precision — and being honest about precision is the entire brand.
"""

from __future__ import annotations

import math

from sieve.suite.runner import CorpusReport


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion. Well-behaved at the small
    counts and near-zero rates this project actually reports, where the normal
    approximation falls apart."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def format_markdown(report: CorpusReport, sieve_name: str = "SIEVE (reference)") -> str:
    lines: list[str] = []
    lines.append("## Results\n")

    # Headline summaries
    lines.append("| Gateway | Attacks contained | False refusals |")
    lines.append("|---|---|---|")
    for t in report.target_names:
        s = report.summary(t)
        fr = ""
        if s.benign_total:
            lo, hi = wilson_interval(s.false_refusals, s.benign_total)
            fr = f"{s.false_refusals}/{s.benign_total} ({lo*100:.1f}–{hi*100:.1f}% 95% CI)"
        else:
            fr = "—"
        lines.append(f"| {t} | {s.contained}/{s.attacks_total} | {fr} |")
    lines.append("")

    # Per-attack matrix
    lines.append("### Attacks\n")
    header = "| ID | Attack | Family | " + " | ".join(report.target_names) + " |"
    lines.append(header)
    lines.append("|" + "---|" * (3 + len(report.target_names)))
    for aid, row in report.attack_matrix.items():
        meta = report.attack_meta[aid]
        cells = []
        for t in report.target_names:
            r = row[t]
            cells.append("✅ contained" if r.contained else "❌ let through")
        lines.append(f"| {aid} | {meta.name} | {meta.family} | " + " | ".join(cells) + " |")
    lines.append("")

    # False refusals, itemised (honesty: name every one)
    if report.benign_matrix:
        lines.append("### False refusals (legitimate transactions wrongly blocked)\n")
        any_fr = False
        for cid, row in report.benign_matrix.items():
            r = row[sieve_name]
            if r.false_refusal:
                any_fr = True
                lines.append(f"- `{cid}` {r.name} — refused as `{r.actual_reason}`")
        if not any_fr:
            lines.append("_None._")
        lines.append("")

    return "\n".join(lines)


def summary_json(report: CorpusReport) -> dict:
    out = report.to_json()
    for s in out["summaries"]:
        if s["benign_total"]:
            lo, hi = wilson_interval(s["false_refusals"], s["benign_total"])
            s["false_refusal_ci95"] = [round(lo, 4), round(hi, 4)]
    return out
