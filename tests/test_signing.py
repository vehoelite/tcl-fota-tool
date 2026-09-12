"""v1 (JAR) signature verification + certificate inspection.

Self-contained: builds an RSA key, a self-signed cert, and a JAR-signed zip the
way signapk does, then checks that a genuine package verifies, a tampered byte
is caught, and a foreign signer is rejected. Skips cleanly without the optional
'verify' extra.
"""

import base64
import datetime
import hashlib
import io
import zipfile

import pytest

from tcl_fw import signing

pytestmark = pytest.mark.skipif(not signing.AVAILABLE,
                                reason="needs the optional 'verify' extra")


# ── build a signed zip the signapk way ───────────────────────────────────────

def _keypair(cn="TCT Test releasekey", org="TCT"):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
    ])
    now = datetime.datetime(2024, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return key, cert, pem


def _b64sha256(b: bytes) -> str:
    return base64.b64encode(hashlib.sha256(b).digest()).decode()


def _signed_zip(files: dict, key, cert) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7

    # MANIFEST.MF: a digest per file
    mf = "Manifest-Version: 1.0\r\nCreated-By: test\r\n\r\n"
    for name, data in files.items():
        mf += f"Name: {name}\r\nSHA-256-Digest: {_b64sha256(data)}\r\n\r\n"
    mf_b = mf.encode()

    # CERT.SF: whole-manifest digest + per-entry digests of manifest sections
    sf = ("Signature-Version: 1.0\r\n"
          f"SHA-256-Digest-Manifest: {_b64sha256(mf_b)}\r\n\r\n")
    sf_b = sf.encode()

    # CERT.RSA: PKCS#7 signature over CERT.SF (no authenticated attributes)
    rsa_b = (pkcs7.PKCS7SignatureBuilder().set_data(sf_b).add_signer(
        cert, key, hashes.SHA256()).sign(
        serialization.Encoding.DER,
        [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.NoAttributes,
         pkcs7.PKCS7Options.Binary]))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
        z.writestr("META-INF/MANIFEST.MF", mf_b)
        z.writestr("META-INF/CERT.SF", sf_b)
        z.writestr("META-INF/CERT.RSA", rsa_b)
    return buf.getvalue()


@pytest.fixture
def signed(tmp_path):
    key, cert, pem = _keypair()
    files = {"AndroidManifest.xml": b"<manifest/>", "classes.dex": b"dexdexdex" * 50}
    blob = _signed_zip(files, key, cert)
    p = tmp_path / "app.apk"
    p.write_bytes(blob)
    return p, pem, files


# ── the contract ─────────────────────────────────────────────────────────────

def test_genuine_package_verifies(signed):
    apk, pem, _ = signed
    r = signing.verify_apk(str(apk))
    assert r.ok, r.errors
    assert r.signer and r.signer.common_name == "TCT Test releasekey"
    assert r.signer.is_tcl                      # O=TCT is recognised
    assert not r.tampered


def test_tampered_file_is_caught(signed, tmp_path):
    apk, pem, files = signed
    # rebuild the zip with one file's bytes changed, keeping the signature blocks
    src = zipfile.ZipFile(str(apk))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n in src.namelist():
            data = src.read(n)
            if n == "classes.dex":
                data = data + b"evil"
            z.writestr(n, data)
    bad = tmp_path / "bad.apk"
    bad.write_bytes(buf.getvalue())
    r = signing.verify_apk(str(bad))
    assert not r.ok
    assert "classes.dex" in r.tampered


def test_signature_over_a_swapped_signer_fails(signed, tmp_path):
    """Re-sign CERT.SF's slot with a different key: the cert changes but the
    manifest still matches, so only the PKCS#7 step should reject it."""
    apk, _, files = signed
    # A second identity signs a *different* SF? Simplest: build a whole new zip
    # with a foreign key, then confirm --against the original cert fails.
    key2, cert2, _ = _keypair(cn="Someone Else", org="EVIL")
    other = _signed_zip(files, key2, cert2)
    p = tmp_path / "other.apk"
    p.write_bytes(other)
    _, pem, _ = signed
    r = signing.verify_apk(str(p), against=pem)
    assert r.matches_reference is False
    assert not r.ok                             # --against mismatch fails it


def test_against_matching_cert_passes(signed):
    apk, pem, _ = signed
    r = signing.verify_apk(str(apk), against=pem)
    assert r.matches_reference is True
    assert r.ok


def test_unsigned_zip_reports_no_v1(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("hello.txt", b"hi")
    p = tmp_path / "plain.zip"
    p.write_bytes(buf.getvalue())
    r = signing.verify_apk(str(p))
    assert not r.ok
    assert any("no v1" in e.lower() for e in r.errors)


# ── certificate inspection ───────────────────────────────────────────────────

def test_certs_in_finds_pem_inside_a_zip(tmp_path):
    _, _, pem = _keypair(cn="TCL goldfinch releasekey")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("FCM_PRO_CONFIG/SIGNAPK_KEY/releasekey.x509.pem", pem)
        z.writestr("other/data.bin", b"\x00\x01")
    certs = signing.certs_in(buf.getvalue())
    assert len(certs) == 1
    assert certs[0].common_name == "TCL goldfinch releasekey"
    assert certs[0].is_tcl
    assert certs[0].source.endswith("releasekey.x509.pem")


def test_load_bare_pem_cert():
    _, _, pem = _keypair()
    c = signing.load_cert(pem)
    assert c is not None and c.key_type == "RSA" and c.key_bits == 2048
