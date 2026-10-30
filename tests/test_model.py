import unittest

from onboard.model import (
    DEFAULT_MATRIX, ControlClass, Criticality, Mode, Severity, Tier, derive_mode, escalate,
    in_scope, matrix_changes, mode_by_criticality, tier_floor, validate_matrix,
)


class DefaultMatrixTest(unittest.TestCase):
    def test_matches_the_spec(self):
        expected = {
            "Critical": ["Enforce", "Enforce", "Enforce"],
            "High": ["Enforce with override", "Enforce", "Enforce"],
            "Medium": ["Advise", "Enforce with override", "Enforce"],
            "Low": ["Advise", "Advise", "Enforce with override"],
            "Informational": ["Report", "Report", "Advise"],
        }
        for severity, modes in expected.items():
            row = DEFAULT_MATRIX[Severity(severity)]
            self.assertEqual([row[c].value for c in Criticality], modes, severity)

    def test_default_is_valid_and_unchanged(self):
        validate_matrix(DEFAULT_MATRIX)
        self.assertEqual(matrix_changes(DEFAULT_MATRIX), [])

    def test_rejects_a_row_that_drops_with_criticality(self):
        matrix = {s: dict(r) for s, r in DEFAULT_MATRIX.items()}
        matrix[Severity.LOW][Criticality.HIGH] = Mode.REPORT
        with self.assertRaisesRegex(ValueError, "lowers the mode"):
            validate_matrix(matrix)

    def test_rejects_a_missing_cell(self):
        matrix = {s: dict(r) for s, r in DEFAULT_MATRIX.items()}
        del matrix[Severity.HIGH][Criticality.LOW]
        with self.assertRaisesRegex(ValueError, "must cover"):
            validate_matrix(matrix)

    def test_reports_changes_from_default(self):
        matrix = {s: dict(r) for s, r in DEFAULT_MATRIX.items()}
        matrix[Severity.LOW][Criticality.LOW] = Mode.REPORT
        self.assertEqual(matrix_changes(matrix), [
            {"severity": "Low", "criticality": "Low", "default": "Advise", "ratified": "Report"}])


class TierTest(unittest.TestCase):
    def test_tiers_are_cumulative(self):
        self.assertTrue(in_scope(ControlClass.CONTAINMENT, Tier.PRIVATE_PREVIEW))
        self.assertFalse(in_scope(ControlClass.SUPERVISION, Tier.PRIVATE_PREVIEW))
        self.assertTrue(in_scope(ControlClass.SUPERVISION, Tier.CONTAINED))
        self.assertFalse(in_scope(ControlClass.HARDENING, Tier.CONTAINED))
        for cls in ControlClass:
            self.assertTrue(in_scope(cls, Tier.HARDENED))

    def test_floors(self):
        for tier in Tier:
            self.assertIs(tier_floor(ControlClass.CONTAINMENT, tier), Mode.ENFORCE)
        self.assertIsNone(tier_floor(ControlClass.SUPERVISION, Tier.PRIVATE_PREVIEW))
        self.assertIs(tier_floor(ControlClass.SUPERVISION, Tier.CONTAINED), Mode.ENFORCE_WITH_OVERRIDE)
        self.assertIs(tier_floor(ControlClass.SUPERVISION, Tier.HARDENED), Mode.ENFORCE_WITH_OVERRIDE)
        self.assertIsNone(tier_floor(ControlClass.HARDENING, Tier.HARDENED))


class DeriveModeTest(unittest.TestCase):
    def test_containment_is_never_permissive(self):
        for tier in Tier:
            for severity in Severity:
                for criticality in Criticality:
                    self.assertIs(derive_mode(severity, criticality, ControlClass.CONTAINMENT, tier),
                                  Mode.ENFORCE)

    def test_supervision_floor_lifts_permissive_cells(self):
        self.assertIs(derive_mode(Severity.INFORMATIONAL, Criticality.LOW, ControlClass.SUPERVISION,
                                  Tier.CONTAINED), Mode.ENFORCE_WITH_OVERRIDE)
        # The floor never lowers a mode the matrix already set higher.
        self.assertIs(derive_mode(Severity.CRITICAL, Criticality.LOW, ControlClass.SUPERVISION,
                                  Tier.CONTAINED), Mode.ENFORCE)

    def test_hardening_follows_the_matrix(self):
        for severity in Severity:
            for criticality in Criticality:
                self.assertIs(derive_mode(severity, criticality, ControlClass.HARDENING, Tier.HARDENED),
                              DEFAULT_MATRIX[severity][criticality])

    def test_out_of_scope_class_is_refused(self):
        with self.assertRaisesRegex(ValueError, "not in scope"):
            derive_mode(Severity.HIGH, Criticality.HIGH, ControlClass.HARDENING, Tier.CONTAINED)

    def test_mode_by_criticality_example_from_spec(self):
        # A Medium supervision control at Contained: floor lifts Low to Enforce with override.
        modes = mode_by_criticality(Severity.MEDIUM, ControlClass.SUPERVISION, Tier.CONTAINED)
        self.assertEqual({c.value: m.value for c, m in modes.items()}, {
            "Low": "Enforce with override", "Moderate": "Enforce with override", "High": "Enforce"})


class EscalateTest(unittest.TestCase):
    def test_takes_the_highest(self):
        self.assertIs(escalate(Mode.ADVISE, Mode.ENFORCE, Mode.REPORT), Mode.ENFORCE)

    def test_needs_a_mode(self):
        with self.assertRaises(ValueError):
            escalate()

    def test_enforcing(self):
        self.assertEqual([m.value for m in Mode if m.enforcing], ["Enforce with override", "Enforce"])


if __name__ == "__main__":
    unittest.main()
