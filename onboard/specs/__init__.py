"""Security specs: what each preventive control must deny (ADR-0003, ADR-0006).

These files are what the security team reviews instead of the generated JSON.
Each `Property` says, in terms of the request, what one control must deny. It
is written from the control's title and objective, never from its guardrail;
Verify proves each generated statement denies exactly that, no more and no
less, over the attacker model in `onboard/adversary.py`.

A service's spec is the shared organization spec (`organization.py`, the
`ORG-*` controls) plus the service's own module, registered in `SERVICES`.

Conventions:
- `deny_when(r, f)` reads the request `r` (only the dimensions in `reads`, plus
  `r.principal`) and the request's facts `f` (`adversary.Facts`).
- Break-glass principals, and approved exceptions for Enforce-with-override
  controls, are exempt from every property except the data perimeter
  (`break_glass_exempt=False`), and only while they are organization
  principals (`adversary.trusted`). That exemption is safe only because
  ORG-C-04 stops anyone else creating, changing or passing those roles.
- The accepted risks are the gaps left open on purpose, each with its reach
  (who can use it and from where). The tests pin each one with a request that
  must stay allowed and boundary requests that must stay denied.
- Equivalent mutants are mutations that change nothing the model can observe,
  each with the reason. Verify skips them; every other mutant must be caught.

Never weaken a property, drop a mutant, or add an equivalent mutant or an
accepted risk to get green; those need a human (AGENTS.md).
"""

from __future__ import annotations

import hashlib
import importlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..adversary import Facts, Property

# The review status of every spec module until the security team signs it off.
PROPOSED = "proposed: needs security team sign-off"
APPROVED = "approved"

# Service prefix -> module under onboard/specs/ with its properties.
SERVICES = {"athena": "athena"}


@dataclass(frozen=True)
class AcceptedRisk:
    id: str
    controls: tuple[str, ...]  # the risk applies while any of these is preventive
    risk: str
    why: str
    owner: str
    status: str
    reach: str  # who can use the gap, and from where


@dataclass(frozen=True)
class EquivalentMutant:
    control: str
    pattern: str   # regular expression over the mutant's description (adversary.mutants)
    reason: str
    when: Callable[[re.Match, Facts], bool] | None = None  # extra condition on the request's facts

    def applies(self, control: str, description: str, facts: Facts) -> bool:
        if control != self.control:
            return False
        m = re.fullmatch(self.pattern, description)
        return bool(m) and (self.when is None or self.when(m, facts))


@dataclass(frozen=True)
class Spec:
    service: str
    properties: tuple[Property, ...]
    accepted_risks: tuple[AcceptedRisk, ...]
    equivalent_mutants: tuple[EquivalentMutant, ...]
    action_review: dict | None
    status: str
    sha256: str  # of the spec's source files, so a change to them shows up
    by_control: dict = field(default_factory=dict)

    def equivalent(self, control: str, description: str, facts: Facts) -> EquivalentMutant | None:
        return next((e for e in self.equivalent_mutants if e.applies(control, description, facts)), None)


class SpecError(ValueError):
    pass


def load_spec(service: str) -> Spec:
    """The organization spec plus the service's own, or SpecError if the service has none."""
    name = SERVICES.get(service)
    if name is None:
        raise SpecError(f"no security spec for {service!r}: write onboard/specs/<module>.py and register it "
                        "in onboard.specs.SERVICES")
    modules = [importlib.import_module(f"{__name__}.organization"), importlib.import_module(f"{__name__}.{name}")]
    digest = hashlib.sha256()
    for module in modules:
        for path in [Path(module.__file__)] + list(getattr(module, "DATA_FILES", ())):
            digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    properties = tuple(p for m in modules for p in m.PROPERTIES)
    by_control = {p.control: p for p in properties}
    if len(by_control) != len(properties):
        raise SpecError(f"the {service} spec states a control twice")
    statuses = {m.STATUS for m in modules}
    return Spec(
        service=service, properties=properties,
        accepted_risks=tuple(r for m in modules for r in m.ACCEPTED_RISKS),
        equivalent_mutants=tuple(e for m in modules for e in m.EQUIVALENT_MUTANTS),
        action_review=getattr(modules[1], "ACTION_REVIEW", None),
        status=APPROVED if statuses == {APPROVED} else PROPOSED,
        sha256=digest.hexdigest(), by_control=by_control,
    )
