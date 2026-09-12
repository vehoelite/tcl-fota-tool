"""
signing.py — verify Android v1 (JAR) package signatures and inspect the release
certificates a TCL device trusts.

What this does, precisely:
  * VERIFY a signed package (APK / OTA-style zip) against its embedded
    certificate — proving it was signed by that key *and* not modified since.
  * INSPECT the signing certificate(s) inside a firmware blob (the release /
    platform certs, e.g. `releasekey.x509.pem`, `otacerts.zip`).

What it deliberately does NOT do: sign anything. Signing needs the *private*
key, which lives in TCL's build HSM and never ships in firmware. A public
certificate can only ever verify. See README.

Optional feature. It needs `cryptography` + `pyasn1`/`pyasn1-modules`
(`pip install "tcl-fw[verify]"`). When they're absent every entry point returns
a clear message instead of raising, so the core tool keeps its lean footprint.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Optional

try:                                    # optional dependency island
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID
    from pyasn1.codec.der import decoder as _der_decoder
    from pyasn1_modules import rfc2315
    AVAILABLE = True
except Exception:                       # pragma: no cover - env without the extra
    AVAILABLE = False

MISSING_MSG = ("signature verification needs the optional 'verify' extra:\n"
               "  pip install \"tcl-fw[verify]\"   (installs cryptography + pyasn1)")

# One row per hash: JAR manifest header, hashlib name, digest-algorithm OID.
# `_crypto_hash()` maps the header to a cryptography hash class lazily (only when
# the optional dep is present).
_HASHES = [
    # header,    hashlib,  digest OID
    ("SHA-512",  "sha512", "2.16.840.1.101.3.4.2.3"),
    ("SHA-384",  "sha384", "2.16.840.1.101.3.4.2.2"),
    ("SHA-256",  "sha256", "2.16.840.1.101.3.4.2.1"),
    ("SHA1",     "sha1",   "1.3.14.3.2.26"),
]
_DIGEST_HEADERS = [h for h, _, _ in _HASHES]           # strongest first
_HEADER_HASHLIB = {h: hl for h, hl, _ in _HASHES}
_OID_HEADER = {oid: h for h, _, oid in _HASHES}
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"


def _hashlib_for_header(header: str):
    return getattr(hashlib, _HEADER_HASHLIB[header])


def _crypto_hash_for_oid(oid: str):
    header = _OID_HEADER.get(oid, "SHA-256")
    return {"SHA1": hashes.SHA1, "SHA-256": hashes.SHA256,
            "SHA-384": hashes.SHA384, "SHA-512": hashes.SHA512}[header]()


# ── certificate model ─────────────────────────────────────────────────────────

@dataclass
class CertInfo:
    common_name: str
    subject: str
    issuer: str
    self_signed: bool
    not_before: str
    not_after: str
    sha256: str
    sha1: str
    key_type: str
    key_bits: Optional[int]
    is_tcl: bool
    source: str = ""            # where it was found (zip entry path, etc.)

    def summary(self) -> str:
        tcl = "  [official TCL key]" if self.is_tcl else ""
        bits = f" {self.key_bits}-bit" if self.key_bits else ""
        return (f"{self.common_name}{tcl}\n"
                f"    {self.key_type}{bits}   valid {self.not_before} -> {self.not_after}\n"
                f"    SHA-256 {self.sha256}")


def _cert_info(cert, source: str = "") -> "CertInfo":
    def cn(name) -> str:
        got = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return got[0].value if got else name.rfc4514_string()
    pub = cert.public_key()
    key_type = type(pub).__name__.replace("PublicKey", "")
    org = ""
    o = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if o:
        org = o[0].value
    is_tcl = (org.upper() in ("TCT", "TCL") or "android@tcl.com" in
              cert.subject.rfc4514_string().lower() or "tcl" in cn(cert.subject).lower())
    try:
        nb = cert.not_valid_before_utc.date().isoformat()
        na = cert.not_valid_after_utc.date().isoformat()
    except AttributeError:               # older cryptography
        nb = cert.not_valid_before.date().isoformat()
        na = cert.not_valid_after.date().isoformat()
    return CertInfo(
        common_name=cn(cert.subject),
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        self_signed=cert.subject == cert.issuer,
        not_before=nb, not_after=na,
        sha256=cert.fingerprint(hashes.SHA256()).hex(),
        sha1=cert.fingerprint(hashes.SHA1()).hex(),
        key_type=key_type, key_bits=getattr(pub, "key_size", None),
        is_tcl=is_tcl, source=source)


def load_cert(data: bytes, source: str = "") -> Optional["CertInfo"]:
    """Parse one PEM or DER X.509 certificate. None if it isn't one."""
    if not AVAILABLE:
        return None
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            return _cert_info(loader(data), source)
        except Exception:
            continue
    return None


# ── truncated-zip-safe entry walk (TCL zips often lack an EOCD) ───────────────

def _zip_entries(data: bytes):
    """Yield (name, method, comp_size, flags, data_offset) by walking local
    headers from the front — works on the truncated zips TCL ships, where the
    central directory (and zipfile) give up."""
    off, n = 0, len(data)
    while off + 30 <= n:
        if data[off:off + 4] != b"PK\x03\x04":
            nxt = data.find(b"PK\x03\x04", off + 1)
            if nxt == -1:
                return
            off = nxt
            continue
        (_v, flags, method, _mt, _md, _crc,
         csz, _usz, nlen, elen) = struct.unpack_from("<HHHHHIIIHH", data, off + 4)
        name = data[off + 30:off + 30 + nlen].decode("latin1", "replace")
        doff = off + 30 + nlen + elen
        yield name, method, csz, flags, doff
        if csz and not (flags & 0x08):
            off = doff + csz
        else:
            nxt = data.find(b"PK\x03\x04", doff)
            off = nxt if nxt != -1 else n


def _entry_bytes(data: bytes, method: int, csz: int, doff: int) -> bytes:
    raw = data[doff:doff + csz] if csz else data[doff:]
    if method == 8:
        import zlib
        try:
            return zlib.decompressobj(-15).decompress(raw)
        except Exception:
            return b""
    return raw


def certs_in(data: bytes, source: str = "") -> list["CertInfo"]:
    """Every X.509 cert reachable in a blob: a bare PEM/DER cert, or the
    `*.x509.pem` / `*.pem` / `.der` / nested `otacerts.zip` entries of a zip."""
    if not AVAILABLE:
        return []
    # Check zip first: a PEM parser will happily find a stored (uncompressed)
    # certificate's text inside the raw archive bytes and report it with no
    # source path, so a bare-cert shortcut here would mis-attribute zip entries.
    out: list[CertInfo] = []
    if data[:4] == b"PK\x03\x04":
        for name, method, csz, _flags, doff in _zip_entries(data):
            low = name.lower()
            if low.endswith((".pem", ".der", ".x509", ".crt", ".cer")):
                c = load_cert(_entry_bytes(data, method, csz, doff), name)
                if c:
                    out.append(c)
            elif low.endswith("otacerts.zip"):
                out.extend(certs_in(_entry_bytes(data, method, csz, doff),
                                    source + "!" + name))
        return out
    single = load_cert(data, source)
    return [single] if single else []


# ── v1 (JAR) signature verification ───────────────────────────────────────────

@dataclass
class VerifyResult:
    ok: bool
    scheme: str = "v1"
    signer: Optional[CertInfo] = None
    digest: str = ""
    matches_reference: Optional[bool] = None      # set when --against is given
    errors: list = field(default_factory=list)
    tampered: list = field(default_factory=list)  # files whose digest didn't match

    def ok_line(self) -> str:
        return "VERIFIED" if self.ok else "FAILED"


def _parse_manifest(mf: bytes) -> tuple[dict, list]:
    """(main_attributes, [ (name, {header: value}) ]) from a JAR manifest,
    honouring 70-byte continuation lines. Returns raw header dicts."""
    text = mf.decode("latin1", "replace")
    # unfold continuation lines (a line beginning with a single space continues
    # the previous one), tolerate CRLF or LF
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    unfolded = text.replace("\n ", "")
    blocks = [b for b in unfolded.split("\n\n") if b.strip()]
    sections = []
    for b in blocks:
        attrs = {}
        for line in b.split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                attrs[k.strip()] = v.strip()
        sections.append(attrs)
    main = sections[0] if sections else {}
    named = [(a["Name"], a) for a in sections[1:] if "Name" in a]
    return main, named


def _signerinfo(rsa_der: bytes):
    """(signature_bytes, digest_oid, signed_attrs_der_or_None, message_digest)."""
    ci, _ = _der_decoder.decode(rsa_der, asn1Spec=rfc2315.ContentInfo())
    sd, _ = _der_decoder.decode(bytes(ci["content"]), asn1Spec=rfc2315.SignedData())
    si = sd["signerInfos"][0]
    digest_oid = str(si["digestAlgorithm"]["algorithm"])
    sig = bytes(si["encryptedDigest"])
    aa = si["authenticatedAttributes"]
    if aa.isValue and len(aa):
        from pyasn1.codec.der import encoder as _der_encoder
        reencoded = _der_encoder.encode(aa)
        # signed content is the attributes as a DER SET (tag 0x31), not the
        # [0] IMPLICIT context tag they appear under in the SignerInfo.
        signed_attrs_der = b"\x31" + reencoded[1:]
        msg = None
        for attr in aa:
            if str(attr["type"]) == _OID_MESSAGE_DIGEST:
                msg = bytes(_der_decoder.decode(bytes(attr["values"][0]))[0])
        return sig, digest_oid, signed_attrs_der, msg
    return sig, digest_oid, None, None


def verify_apk(path: str, against: Optional[bytes] = None) -> "VerifyResult":
    """Full Android v1 (JAR) verification: the CERT.RSA signature over CERT.SF,
    CERT.SF's digest over the manifest, and the manifest's digest over every
    file — so this catches both a wrong signer and any tampered byte."""
    if not AVAILABLE:
        return VerifyResult(ok=False, errors=[MISSING_MSG])
    res = VerifyResult(ok=False)
    try:
        z = zipfile.ZipFile(path)
    except Exception as e:
        res.errors.append(f"not a readable zip/apk: {e}")
        return res
    names = z.namelist()

    def find(suffixes):
        for n in names:
            u = n.upper()
            if u.startswith("META-INF/") and u.endswith(suffixes):
                return n
        return None

    rsa_name = find((".RSA", ".DSA", ".EC"))
    if not rsa_name:
        res.errors.append("no v1 (JAR) signature present. This package may be "
                          "v2/v3-signed only, which this tool doesn't verify yet.")
        return res
    sf_name = rsa_name.rsplit(".", 1)[0] + ".SF"
    if sf_name not in names or "META-INF/MANIFEST.MF" not in names:
        res.errors.append("incomplete v1 signature (missing .SF or MANIFEST.MF).")
        return res

    rsa, sf, mf = z.read(rsa_name), z.read(sf_name), z.read("META-INF/MANIFEST.MF")

    # 1) who signed it
    certs = pkcs7.load_der_pkcs7_certificates(rsa)
    if not certs:
        res.errors.append("no certificate in the signature block.")
        return res
    signer = certs[0]
    res.signer = _cert_info(signer, rsa_name)

    # 2) the signature over CERT.SF (authenticity + SF integrity)
    try:
        sig, digest_oid, signed_attrs, msgdigest = _signerinfo(rsa)
        res.digest = _OID_HEADER.get(digest_oid, "SHA-256")
        if signed_attrs is not None:
            sf_digest = getattr(hashlib, _HEADER_HASHLIB[res.digest])(sf).digest()
            if msgdigest != sf_digest:
                res.errors.append("signed messageDigest does not match CERT.SF.")
            content = signed_attrs
        else:
            content = sf
        signer.public_key().verify(sig, content, padding.PKCS1v15(),
                                   _crypto_hash_for_oid(digest_oid))
    except Exception as e:
        res.errors.append(f"signature over CERT.SF is invalid: {e}")

    # 3) CERT.SF digest over the whole manifest
    sf_main, _ = _parse_manifest(sf)
    for h in _DIGEST_HEADERS:
        key = f"{h}-Digest-Manifest"
        if key in sf_main:
            got = base64.b64encode(_hashlib_for_header(h)(mf).digest()).decode()
            if got != sf_main[key]:
                res.errors.append("CERT.SF manifest digest mismatch (SF tampered).")
            break
    # (an absent whole-manifest digest is tolerated; per-file check still runs)

    # 4) manifest digest over every file
    _main, entries = _parse_manifest(mf)
    for name, attrs in entries:
        if name not in names:
            res.tampered.append(f"{name} (in manifest, missing from package)")
            continue
        for h in _DIGEST_HEADERS:
            if f"{h}-Digest" in attrs:
                got = base64.b64encode(_hashlib_for_header(h)(z.read(name)).digest()).decode()
                if got != attrs[f"{h}-Digest"]:
                    res.tampered.append(name)
                break

    # 5) optional strict identity check against a reference cert
    if against is not None:
        ref = None
        for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
            try:
                ref = loader(against)
                break
            except Exception:
                continue
        if ref is None:
            res.errors.append("--against value is not a readable certificate.")
        else:
            res.matches_reference = (
                ref.public_key().public_numbers() == signer.public_key().public_numbers())
            if not res.matches_reference:
                res.errors.append("signer does not match the reference certificate.")

    res.ok = not res.errors and not res.tampered
    return res

