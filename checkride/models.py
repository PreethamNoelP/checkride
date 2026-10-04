"""Data model shared by every rule: what a problem looks like (Finding)
and how a category tallies up (CategoryResult)."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    """One specific problem at one specific place in the scanned code."""

    rule: str      # machine id of the rule, e.g. "human-oversight"
    file: str      # path of the scanned file, relative to the scan root
    line: int      # 1-based line number of the offending code
    message: str   # what is wrong, in plain language
    fix: str       # the concrete change that would clear this finding
    critical: bool = False  # True if this alone must fail CI, independent of score
    column: int = 0         # 1-based column of the offending code, 0 if unknown
    function: str | None = None  # qualified name of the enclosing function


@dataclass
class CategoryResult:
    """Outcome of one rule category over an entire scan.

    Rules only count: every place the rule applies bumps `sites`, every
    compliant one bumps `passed`. Points are derived here, nowhere else.
    """

    name: str    # human label, e.g. "Human oversight"
    weight: int  # max points this category contributes (out of 100)
    sites: int = 0    # number of places the rule applied
    passed: int = 0   # how many of those places were compliant
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Points earned. A rule that never applied cannot be failed."""
        if self.sites == 0:
            return float(self.weight)
        return self.weight * (self.passed / self.sites)
