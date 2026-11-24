import pytest

from tcl_fw import reporting


@pytest.fixture(autouse=True)
def _never_report_to_the_live_registry(monkeypatch):
    """Tests exercise failure paths on purpose; none of that may reach the real
    community registry. test_reporting.py re-patches _post to capture."""
    monkeypatch.setattr(reporting, "_post", lambda url, payload: None)


@pytest.fixture(autouse=True)
def _no_retry_waits(monkeypatch):
    """Transient-error retries (fota.RETRY_DELAYS) must not slow the suite down."""
    from tcl_fw import fota

    monkeypatch.setattr(fota, "RETRY_DELAYS", (0.0, 0.0))
    monkeypatch.setattr(fota.random, "uniform", lambda a, b: 0.0)
