"""Run the corpus against every target and collect the results.

For each attack, a fresh World is created and every target is built from THAT
world, so within a single attack row all gateways face byte-identical inputs and
the same trusted roots. Across attacks, state is fresh, so one attack's charges
never bleed into another's budget.

The output is a matrix — attack x target — plus per-target summaries. That
matrix is the differential: read down a column to see how one gateway did, read
across a row to see which gateways an attack defeats.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sieve.suite.corpus import Attack, AttackResult, BenignCase, BenignResult
from sieve.suite.targets import all_targets
from sieve.suite.world import World


@dataclass(frozen=True, slots=True)
class TargetSummary:
    target: str
    contained: int
    attacks_total: int
    false_refusals: int
    benign_total: int

    @property
    def containment_rate(self) -> float:
        return self.contained / self.attacks_total if self.attacks_total else 0.0

    def to_json(self) -> dict:
        return {
            "target": self.target,
            "contained": self.contained,
            "attacks_total": self.attacks_total,
            "containment_rate": round(self.containment_rate, 4),
            "false_refusals": self.false_refusals,
            "benign_total": self.benign_total,
        }


@dataclass
class CorpusReport:
    target_names: list[str]
    # attack_id -> target_name -> AttackResult
    attack_matrix: dict[str, dict[str, AttackResult]] = field(default_factory=dict)
    attack_meta: dict[str, AttackResult] = field(default_factory=dict)  # any target, for name/family
    # case_id -> target_name -> BenignResult
    benign_matrix: dict[str, dict[str, BenignResult]] = field(default_factory=dict)
    benign_meta: dict[str, BenignResult] = field(default_factory=dict)

    def summary(self, target: str) -> TargetSummary:
        contained = sum(
            1 for row in self.attack_matrix.values() if row[target].contained
        )
        false_refusals = sum(
            1 for row in self.benign_matrix.values() if row[target].false_refusal
        )
        return TargetSummary(
            target=target,
            contained=contained,
            attacks_total=len(self.attack_matrix),
            false_refusals=false_refusals,
            benign_total=len(self.benign_matrix),
        )

    def to_json(self) -> dict:
        return {
            "targets": self.target_names,
            "summaries": [self.summary(t).to_json() for t in self.target_names],
            "attacks": {
                aid: {t: row[t].to_json() for t in self.target_names}
                for aid, row in self.attack_matrix.items()
            },
            "benign": {
                cid: {t: row[t].to_json() for t in self.target_names}
                for cid, row in self.benign_matrix.items()
            },
        }


def run_corpus(
    attacks: list[Attack],
    benign: list[BenignCase],
    *,
    seed_now=None,
) -> CorpusReport:
    # Determine target names from a probe world so the report is shaped before
    # the run.
    probe = World(now=seed_now)
    target_names = [t.name for t in all_targets(probe)]
    report = CorpusReport(target_names=target_names)

    for attack in attacks:
        world = World(now=seed_now)
        targets = {t.name: t for t in all_targets(world)}
        row: dict[str, AttackResult] = {}
        for name, target in targets.items():
            row[name] = attack.run(target, world)
        report.attack_matrix[attack.attack_id] = row
        report.attack_meta[attack.attack_id] = next(iter(row.values()))

    for case in benign:
        world = World(now=seed_now)
        targets = {t.name: t for t in all_targets(world)}
        row_b: dict[str, BenignResult] = {}
        for name, target in targets.items():
            row_b[name] = case.run(target, world)
        report.benign_matrix[case.case_id] = row_b
        report.benign_meta[case.case_id] = next(iter(row_b.values()))

    return report
