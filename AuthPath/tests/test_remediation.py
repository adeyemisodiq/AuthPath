from authpath.engine.remediation import get_remediation, get_all_remediations
from authpath.engine.evaluator import VIOLATION, OVER_RESTRICTION, PASS, INCONCLUSIVE


def test_bola_violation_gets_ownership_advice():
    note = get_remediation(VIOLATION, "API1:2023 Broken Object Level Authorization")
    assert "ownership" in note.lower()


def test_bfla_violation_gets_role_check_advice():
    note = get_remediation(VIOLATION, "API5:2023 Broken Function Level Authorization")
    assert "role" in note.lower() or "permission" in note.lower()


def test_over_restriction_gets_its_own_advice():
    note = get_remediation(OVER_RESTRICTION, None)
    assert "too strict" in note.lower() or "policy" in note.lower()


def test_pass_and_inconclusive_with_no_exposure_get_nothing():
    assert get_remediation(PASS, None) is None
    assert get_remediation(INCONCLUSIVE, None) is None


def test_exposed_fields_take_priority_and_name_the_field():
    note = get_remediation(PASS, None, exposed_fields=["password_hash"])
    assert "password_hash" in note


def test_violation_plus_exposure_yields_two_separate_notes():
    """A VIOLATION that also leaks a field needs BOTH fixes - fixing
    access control alone would not stop the leak for allowed subjects."""
    notes = get_all_remediations(
        VIOLATION, "API1:2023 Broken Object Level Authorization",
        exposed_fields=["internal_risk_score"],
    )
    assert len(notes) == 2
    assert any("ownership" in n.lower() for n in notes)
    assert any("internal_risk_score" in n for n in notes)


def test_pass_with_exposure_yields_one_note():
    notes = get_all_remediations(PASS, None, exposed_fields=["internal_risk_score"])
    assert len(notes) == 1
    assert "internal_risk_score" in notes[0]


def test_clean_pass_yields_no_notes():
    assert get_all_remediations(PASS, None, exposed_fields=None) == []
