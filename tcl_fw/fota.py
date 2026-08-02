"""
fota.py — client for TCL's FOTA download servers.

Talks to master.tctsdc.com the way the on-device FOTA app does: signs each
request with a VK (SHA-1 over the ordered params plus a shared secret), then
parses the XML fileset. Two secrets are used:

  * OLD  — the legacy decimal "VDKEY", signs download_request.php (the fileset
           + slave hosts for a known tv/fw_id).
  * NEW  — a binary passphrase, signs check_new.php (used to auto-discover a
           device's latest tv/fw_id from just its curef).

No account, no Google, no dongle — only the public service credentials the app
itself posts (see crypto.ENC_ACCOUNT / ENC_PASSWORD).
"""

from __future__ import annotations

import http.client
import random
import ssl
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from .crypto import ENC_ACCOUNT, ENC_PASSWORD

SERVER = "master.tctsdc.com"
USER_AGENT = "com.tcl.fota.system/7.2321.07.14078.141.0 , Android"
_SSL = ssl._create_unverified_context()

# download_request.php signing secret — the legacy decimal VDKEY (live-proven).
_OLD = (
    "1271941121281905392291845155542171963889169361242115412511417616616958244916823523421516924614"
    "3771311619514022614511610020510420117572167139126116825320315911818610818366126430165962312128"
    "72211620511861302106446924625728571011411121471811641125920123641181975581511602312222261817375"
    "462445966911723844130106116313122624220514"
)
# check_new.php signing secret — the binary passphrase (used for tv/fw_id
# discovery). Decodes to the ASCII string "How are you get this key word?".
_NEW = "".join(
    format(b, "08b") for b in b"How are you get this key word?"
)


@dataclass
class FileEntry:
    file_id: str
    rel_url: str
    size: int = 0


@dataclass
class DownloadInfo:
    curef: str
    tv: str
    fw_id: str
    slave: Optional[str]
    encslave: Optional[str]
    files: list[FileEntry] = field(default_factory=list)

    def by_id(self) -> dict[str, str]:
        return {f.file_id: f.rel_url for f in self.files}


def salt() -> str:
    return "%d%06d" % (int(time.time() * 1000), random.randint(0, 999999))


def vk(params: "OrderedDict[str, str]", secret: str) -> str:
    """VK = SHA-1 over 'k1=v1&k2=v2&...&kN=vN{secret}' (secret appended to the
    last value, no trailing '&'), lowercase hex."""
    import hashlib
    items = list(params.items())
    q = "".join(
        ("%s=%s%s" % (k, v, secret)) if i == len(items) - 1 else ("%s=%s&" % (k, v))
        for i, (k, v) in enumerate(items)
    )
    return hashlib.sha1(q.encode()).hexdigest()


def _post_xml(path: str, params: dict, timeout: int = 30) -> ET.Element:
    req = urllib.request.Request(
        "https://%s/%s" % (SERVER, path),
        data=urllib.parse.urlencode(params).encode(),
        headers={"User-Agent": USER_AGENT},
    )
    raw = urllib.request.urlopen(req, timeout=timeout, context=_SSL).read()
    return ET.fromstring(raw.decode("utf-8", "replace"))


def discover(curef: str, fv: str = "000000", mode: int = 4) -> tuple[Optional[str], Optional[str]]:
    """Auto-discover (tv, fw_id) for a curef via check_new.php. fv=000000 poses
    as a 'very old' build so the server always offers the latest full image."""
    pre = OrderedDict(
        id="543212345000000", salt=salt(), curef=curef, fv=fv,
        type="Firmware", mode=str(mode), cltp="10",
    )
    p = OrderedDict(pre)
    p["vk"] = vk(pre, _NEW)
    p["cktp"] = "2"; p["rtd"] = "1"; p["chnl"] = "2"; p["osvs"] = "15"; p["ckot"] = "2"
    try:
        root = _post_xml("check_new.php", p, timeout=25)
        return root.findtext(".//TV"), root.findtext(".//FW_ID")
    except Exception:
        return None, None


def request_download(curef: str, tv: str, fw_id: str,
                     fv: str = "AAA000", mode: int = 4) -> DownloadInfo:
    """POST download_request.php -> slaves + the full FILE_LIST. foot=1 makes the
    server return resolvable /body/ paths for FULL (mode 4)."""
    pre = OrderedDict(
        id="543212345000000", salt=salt(), curef=curef, fv=fv, tv=tv,
        type="Firmware", fw_id=fw_id, mode=str(mode), cltp="10",
    )
    p = OrderedDict(pre)
    p["vk"] = vk(pre, _OLD)
    p["cktp"] = "2"; p["rtd"] = "1"; p["foot"] = "1"; p["chnl"] = "2"
    root = _post_xml("download_request.php", p, timeout=30)

    sl = root.find("SLAVE_LIST")
    slave = sl.findtext("SLAVE") if sl is not None else None
    encslave = sl.findtext("ENCRYPT_SLAVE") if sl is not None else None
    files: list[FileEntry] = []
    fl = root.find("FILE_LIST")
    if fl is not None:
        for f in fl.findall("FILE"):
            fid = f.findtext("FILE_ID")
            rel = f.findtext("DOWNLOAD_URL")
            if fid and rel:
                files.append(FileEntry(fid, rel, int(f.findtext("SIZE") or 0)))
    return DownloadInfo(curef, tv, fw_id, slave, encslave, files)


def fetch_header(encslave: str, rel: str, timeout: int = 120) -> bytes:
    """POST encrypt_header.php on an encrypt slave -> the raw encrypted header blob."""
    body = urllib.parse.urlencode(
        {"account": ENC_ACCOUNT, "password": ENC_PASSWORD, "address": rel}
    ).encode()
    conn = http.client.HTTPConnection(encslave, timeout=timeout)
    try:
        conn.request(
            "POST", "/encrypt_header.php", body,
            {"Content-Type": "application/x-www-form-urlencoded",
             "User-Agent": USER_AGENT, "Content-Length": str(len(body))},
        )
        resp = conn.getresponse()
        return resp.read()
    finally:
        conn.close()


def body_size(slave: str, rel: str, timeout: int = 25) -> int:
    """Range-probe a body. Returns total size, 0 for an empty body (HTTP 416 or
    a zero-length range) meaning the image lives in the encrypted header, or -1
    on network error."""
    try:
        req = urllib.request.Request(
            "http://%s%s" % (slave, rel),
            headers={"User-Agent": USER_AGENT, "Range": "bytes=0-1"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            cr = r.headers.get("Content-Range", "")
            if "/" in cr:
                return int(cr.split("/")[-1])
            return len(r.read())
    except Exception as e:
        if getattr(e, "code", None) == 416:
            return 0
        return -1


def body_head(slave: str, rel: str, n: int = 64, timeout: int = 25) -> bytes:
    """Fetch the first n bytes of a body (for content-magic naming without a full pull)."""
    try:
        req = urllib.request.Request(
            "http://%s%s" % (slave, rel),
            headers={"User-Agent": USER_AGENT, "Range": "bytes=0-%d" % (n - 1)},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(n)
    except Exception:
        return b""


def manifest(curef: str, fv: str = "000000",
             mode: int = 4) -> tuple[dict[str, str], Optional[str]]:
    """check_new.php -> ({FILE_ID: coded_filename}, sca_FILE_ID). Used to give
    partitions their server-authoritative names. fv=000000 = universal 'very old'."""
    pre = OrderedDict(
        id="543212345000000", salt=salt(), curef=curef, fv=fv,
        type="Firmware", mode=str(mode), cltp="10",
    )
    p = OrderedDict(pre)
    p["vk"] = vk(pre, _NEW)
    p["cktp"] = "2"; p["rtd"] = "1"; p["chnl"] = "2"; p["osvs"] = "15"; p["ckot"] = "2"
    try:
        root = _post_xml("check_new.php", p, timeout=25)
    except Exception:
        return {}, None
    m: dict[str, str] = {}
    sca: Optional[str] = None
    for f in root.iter("FILE"):
        fid = f.findtext("FILE_ID")
        nm = f.findtext("FILENAME")
        if fid:
            m[fid] = nm or ""
        if nm and nm.endswith(".sca"):
            sca = fid
    return m, sca


def resolve(curef: str, tv: Optional[str] = None, fw_id: Optional[str] = None,
            mode: int = 4) -> tuple[str, Optional[str], Optional[str]]:
    """Fill in a missing tv/fw_id by discovery, also trying the '-V' carrier
    variant of the curef. Returns (curef, tv, fw_id) — any may still be None if
    the server has nothing."""
    if tv and fw_id:
        return curef, tv, fw_id
    candidates = [curef] if curef.endswith("-V") else [curef, curef + "-V"]
    for cand in candidates:
        ctv, cfw = discover(cand, mode=mode)
        if ctv and cfw:
            return cand, tv or ctv, fw_id or cfw
    return curef, tv, fw_id
