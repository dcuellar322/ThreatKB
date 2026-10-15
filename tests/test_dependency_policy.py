from datetime import date, datetime, timezone
import pytest
from scripts.audit_dependencies import cutoff_for, validate_evidence, python_pins


def test_age_gate_checks_boundary_timezone_and_exact_lock_coverage():
    cutoff = cutoff_for(date(2026, 10, 15), 10)
    assert cutoff == datetime(2026, 10, 5, tzinfo=timezone.utc)
    pins = [("example", "1.0")]
    good = [{"name": "example", "version": "1.0", "published": "2026-10-05T00:00:00Z"}]
    validate_evidence(pins, good, cutoff)
    for published in ["2026-10-05T00:00:01Z", "2026-10-04T00:00:00"]:
        with pytest.raises(ValueError):
            validate_evidence(pins, [{**good[0], "published": published}], cutoff)
    with pytest.raises(ValueError):
        validate_evidence(pins, [], cutoff)
    with pytest.raises(ValueError):
        validate_evidence(pins, good * 2, cutoff)
    with pytest.raises(ValueError):
        cutoff_for(date(2026, 10, 15), 9)


def test_python_age_audit_includes_development_lock_and_rejects_ranges(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==3.1.3\n")
    (tmp_path / "requirements-dev.txt").write_text("Flask==3.1.3\npytest==9.1.1\n")
    assert python_pins(tmp_path) == [("flask", "3.1.3"), ("pytest", "9.1.1")]
    (tmp_path / "requirements-dev.txt").write_text("pytest>=9\n")
    with pytest.raises(ValueError):
        python_pins(tmp_path)
