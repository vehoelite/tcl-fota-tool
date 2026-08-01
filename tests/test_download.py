"""Tests for stream_body's resume / already-complete handling."""

import email.message
import os
import urllib.error
import urllib.request

import pytest

from tcl_fw import download


def _http_error(code: int, content_range: str | None = None):
    hdrs = email.message.Message()
    if content_range:
        hdrs["Content-Range"] = content_range
    return urllib.error.HTTPError("http://x/y", code, "err", hdrs, None)


def test_content_range_total_parses_star_form():
    assert download._content_range_total("bytes */12345") == 12345
    assert download._content_range_total("bytes 0-1/999") == 999
    assert download._content_range_total(None) is None
    assert download._content_range_total("garbage") is None


def test_stream_body_treats_416_at_eof_as_complete(tmp_path, monkeypatch):
    # A fully-downloaded file: re-pulling must NOT raise; it's already done.
    dest = tmp_path / "already.img"
    dest.write_bytes(b"\x00" * 100)

    def fake_urlopen(req, timeout=0):
        raise _http_error(416, "bytes */100")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    seen = []
    got = download.stream_body("slave", "/rel", str(dest),
                               on_progress=lambda g, t: seen.append((g, t)))
    assert got == 100
    assert seen[-1] == (100, 100)


def test_stream_body_restarts_when_local_longer_than_remote(tmp_path, monkeypatch):
    # Local file is bigger than the server's file -> corrupt -> redownload clean.
    dest = tmp_path / "toolong.img"
    dest.write_bytes(b"\x00" * 200)
    calls = {"n": 0}

    class FakeResp:
        headers = {"Content-Length": "50"}
        status = 200
        def read(self, n=0):
            if calls["n"] == 0:
                calls["n"] = 1
                return b"\x01" * 50
            return b""
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=0):
        # First call (with Range) 416s; the clean retry (no Range) succeeds.
        if req.headers.get("Range"):
            raise _http_error(416, "bytes */50")
        return FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    got = download.stream_body("slave", "/rel", str(dest))
    assert got == 50
    assert os.path.getsize(dest) == 50
