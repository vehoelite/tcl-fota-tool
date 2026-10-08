import pytest

from tcl_fw import reporting


@pytest.fixture(autouse=True)
def _never_report_to_the_live_registry(monkeypatch):
    """Tests exercise failure paths on purpose; none of that may reach the real
    community registry. test_reporting.py re-patches _post to capture."""
    monkeypatch.setattr(reporting, "_post", lambda url, payload: None)
