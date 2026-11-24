"""Fixes for bugs caught by the anonymous error reports (v4.5.2)."""

from __future__ import annotations

import io
import socket
import urllib.error

import pytest

from tcl_fw import cli, fota, puller
from tcl_fw.fota import DownloadInfo, FileEntry


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(fota.time, "sleep", lambda s: None)


def test_transient_server_errors_are_retried(monkeypatch):
    calls = []

    def flaky(path, params, timeout=30):
        calls.append(1)
        if len(calls) < 3:
            raise fota.ServerError("TCL's update server returned an invalid response")
        return "ok"

    monkeypatch.setattr(fota, "_post_xml_once", flaky)
    assert fota._post_xml("download_request.php", {}) == "ok" and len(calls) == 3


def test_permanent_errors_are_not_retried(monkeypatch):
    calls = []

    def gone(path, params, timeout=30):
        calls.append(1)
        raise urllib.error.HTTPError("u", 404, "nf", {}, None)

    monkeypatch.setattr(fota, "_post_xml_once", gone)
    with pytest.raises(urllib.error.HTTPError):
        fota._post_xml("x", {})
    assert len(calls) == 1
    assert fota.is_transient(ConnectionResetError()) and fota.is_transient(socket.timeout())
    assert not fota.is_transient(ValueError())


def test_header_fetch_survives_a_connection_reset(monkeypatch):
    seq = [ConnectionResetError(10054, "reset"), b"\x00" * 32]

    def once(encslave, rel, timeout=120):
        x = seq.pop(0)
        if isinstance(x, Exception):
            raise x
        return x

    monkeypatch.setattr(fota, "_fetch_header_once", once)
    assert fota.fetch_header("enc.example", "/x") == b"\x00" * 32


def test_cli_prints_a_plain_message_for_a_server_error(monkeypatch, capsys):
    def boom():
        raise fota.ServerError("TCL's update server returned an invalid response to download_request.php")

    monkeypatch.setattr(cli, "app", boom)
    monkeypatch.setattr(cli.reporting, "report_exception", lambda *a, **k: True)
    with pytest.raises(SystemExit) as ex:
        cli.main()
    assert ex.value.code == 1
    out = capsys.readouterr().out
    assert "already retried" in out and "Traceback" not in out


def test_console_cannot_crash_on_a_character(monkeypatch):

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    monkeypatch.setattr(cli.sys, "stdout", stream)
    cli._safe_console()
    stream.write("files → out/ ✓\n")
    stream.flush()
    assert b"files ? out/ ?" in raw.getvalue()


def test_a_malformed_header_skips_one_file_not_the_pull(monkeypatch):
    info = DownloadInfo("CUREF", "TV", "1", None, "enc.example", [FileEntry("42", "/a/b", 100)])
    plan = puller.PullPlan(info)
    monkeypatch.setattr(fota, "fetch_header", lambda *a, **k: b"\x01" * 17)   # not whole AES blocks
    assert puller._resolve_name(plan, info.files[0], is_small=True) is None
    assert "42" in plan.rejected
