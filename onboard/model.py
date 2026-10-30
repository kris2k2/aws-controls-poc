"""The control model: tiers, classes, criticality, severity and enforcement modes.

A control's enforcement mode is derived, never set by hand: it is the higher of
the ratified decision matrix (severity by criticality) and the floor of the
maturity tier for the control's class.
"""

from __future__ import annotations

from enum import Enum
from typing import Mapping


class _Ordered(str, Enum):
    """A string enum whose members compare by declaration order."""

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)

    def __lt__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self.rank >= other.rank


class Tier(_Ordered):
    PRIVATE_PREVIEW = "Private Preview"
    CONTAINED = "Contained"
    HARDENED = "Hardened"


class ControlClass(_Ordered):
    CONTAINMENT = "Containment"
    SUPERVISION = "Supervision"
    HARDENING = "Hardening"


class Criticality(_Ordered):
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"


class Severity(_Ordered):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Mode(_Ordered):
    REPORT = "Report"
    ADVISE = "Advise"
    ENFORCE_WITH_OVERRIDE = "Enforce with override"
    ENFORCE = "Enforce"

    @property
    def enforcing(self) -> bool:
        return self >= Mode.ENFORCE_WITH_OVERRIDE


# The class whose controls a tier first brings into scope.
EARLIEST_TIER = {
    ControlClass.CONTAINMENT: Tier.PRIVATE_PREVIEW,
    ControlClass.SUPERVISION: Tier.CONTAINED,
    ControlClass.HARDENING: Tier.HARDENED,
}

S, C, M = Severity, Criticality, Mode
DEFAULT_MATRIX: Mapping[Severity, Mapping[Criticality, Mode]] = {
    S.CRITICAL: {C.LOW: M.ENFORCE, C.MODERATE: M.ENFORCE, C.HIGH: M.ENFORCE},
    S.HIGH: {C.LOW: M.ENFORCE_WITH_OVERRIDE, C.MODERATE: M.ENFORCE, C.HIGH: M.ENFORCE},
    S.MEDIUM: {C.LOW: M.ADVISE, C.MODERATE: M.ENFORCE_WITH_OVERRIDE, C.HIGH: M.ENFORCE},
    S.LOW: {C.LOW: M.ADVISE, C.MODERATE: M.ADVISE, C.HIGH: M.ENFORCE_WITH_OVERRIDE},
    S.INFORMATIONAL: {C.LOW: M.REPORT, C.MODERATE: M.REPORT, C.HIGH: M.ADVISE},
}
del S, C, M


def in_scope(control_class: ControlClass, tier: Tier) -> bool:
    """Tiers are cumulative: a class applies from its earliest tier onwards."""
    return tier >= EARLIEST_TIER[control_class]


def tier_floor(control_class: ControlClass, tier: Tier) -> Mode | None:
    """The lowest mode a control of this class may have at this tier.

    Containment is Enforce at every tier. Supervision is at least Enforce with
    override from Contained. Hardening has no floor; the matrix decides.
    Returns None when the class has no floor (or is out of scope).
    """
    if not in_scope(control_class, tier):
        return None
    if control_class is ControlClass.CONTAINMENT:
        return Mode.ENFORCE
    if control_class is ControlClass.SUPERVISION:
        return Mode.ENFORCE_WITH_OVERRIDE
    return None


def validate_matrix(matrix: Mapping[Severity, Mapping[Criticality, Mode]]) -> None:
    """A ratified matrix covers every cell and never drops as criticality rises."""
    for severity in Severity:
        row = matrix.get(severity)
        if row is None or set(row) != set(Criticality):
            raise ValueError(f"matrix row {severity.value!r} must cover Low, Moderate and High")
        modes = [row[c] for c in Criticality]
        if modes != sorted(modes):
            raise ValueError(f"matrix row {severity.value!r} lowers the mode as criticality rises")


def matrix_changes(matrix: Mapping[Severity, Mapping[Criticality, Mode]]) -> list[dict]:
    """Cells that differ from the default; each one is a checker item."""
    return [
        {"severity": s.value, "criticality": c.value,
         "default": DEFAULT_MATRIX[s][c].value, "ratified": matrix[s][c].value}
        for s in Severity for c in Criticality
        if matrix[s][c] is not DEFAULT_MATRIX[s][c]
    ]


def derive_mode(severity: Severity, criticality: Criticality, control_class: ControlClass,
                tier: Tier, matrix: Mapping[Severity, Mapping[Criticality, Mode]] = DEFAULT_MATRIX) -> Mode:
    """The higher of the ratified matrix and the tier floor."""
    if not in_scope(control_class, tier):
        raise ValueError(f"{control_class.value} controls are not in scope at {tier.value}")
    mode = matrix[severity][criticality]
    floor = tier_floor(control_class, tier)
    return max(mode, floor) if floor else mode


def mode_by_criticality(severity: Severity, control_class: ControlClass, tier: Tier,
                        matrix: Mapping[Severity, Mapping[Criticality, Mode]] = DEFAULT_MATRIX) -> dict[Criticality, Mode]:
    """Every control record carries its mode for all three criticalities."""
    return {c: derive_mode(severity, c, control_class, tier, matrix) for c in Criticality}


def escalate(*modes: Mode) -> Mode:
    """A shared control keeps the highest mode any onboarded service needs."""
    if not modes:
        raise ValueError("escalate needs at least one mode")
    return max(modes)
