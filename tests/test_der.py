import base64
import datetime as dt
import subprocess
import shutil

import pytest

from trustsweep.der import DERError, load_certs, parse_der, parse_jks, parse_pem_bundle
from conftest import fixture_path, pem, write_jks


def test_parses_subject_and_dates():
    certs, bad = parse_pem_bundle(pem("corp-root.pem").encode())
    assert bad == 0 and len(certs) == 1
    c = certs[0]
    assert c.common_name == "Acme Corp Root CA"
    assert c.organization == "Acme Corp"
    assert ("C", "US") in c.subject
    assert c.issuer == c.subject  # self-signed
    assert c.not_before == dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
    assert c.not_after == dt.datetime(2040, 1, 1, tzinfo=dt.timezone.utc)


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs openssl")
@pytest.mark.parametrize("name", ["corp-root.pem", "shady-root.pem", "expired-root.pem", "public-x1.pem"])
def test_fingerprint_matches_openssl(name):
    out = subprocess.check_output(["openssl", "x509", "-in", fixture_path(name), "-noout", "-fingerprint", "-sha256"], text=True)
    expected = out.strip().split("=", 1)[1]
    assert load_certs(pem(name).encode())[0][0].fingerprint == expected


def test_der_file_and_pem_roundtrip():
    with open(fixture_path("corp-root.der"), "rb") as fh:
        certs, bad, fmt = load_certs(fh.read())
    assert fmt == "der" and len(certs) == 1
    again = load_certs(certs[0].pem().encode())[0][0]
    assert again.sha256 == certs[0].sha256


def test_bundle_with_comments_and_garbage_block():
    data = ("# Comment line\n" + pem("public-x1.pem") + "\nlabel\n" + pem("public-x2.pem")
            + "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    certs, bad = parse_pem_bundle(data.encode())
    assert [c.common_name for c in certs] == ["Public Root X1", "Public Root X2"]
    assert bad == 1


def test_trusted_certificate_header_supported():
    data = pem("corp-root.pem").replace("BEGIN CERTIFICATE", "BEGIN TRUSTED CERTIFICATE").replace(
        "END CERTIFICATE", "END TRUSTED CERTIFICATE")
    assert parse_pem_bundle(data.encode())[0][0].common_name == "Acme Corp Root CA"


def test_expiry_helpers():
    now = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
    old = load_certs(pem("expired-root.pem").encode())[0][0]
    soon = load_certs(pem("soon-root.pem").encode())[0][0]
    assert old.expired(now) and not old.expires_within(90, now)
    assert not soon.expired(now) and soon.expires_within(90, now) and not soon.expires_within(30, now)


@pytest.mark.parametrize("version", [1, 2])
def test_jks_trusted_entries(tmp_path, version):
    p = tmp_path / "cacerts"
    write_jks(str(p), [pem("public-x1.pem"), pem("corp-root.pem")], version=version)
    certs, bad, fmt = load_certs(p.read_bytes())
    assert fmt == "jks" and bad == 0
    assert [c.common_name for c in certs] == ["Public Root X1", "Acme Corp Root CA"]


def test_jks_rejects_non_jks():
    with pytest.raises(DERError):
        parse_jks(b"not a keystore at all")


def test_parse_der_rejects_junk():
    with pytest.raises(DERError):
        parse_der(b"\x02\x01\x00")
    with pytest.raises(DERError):
        parse_der(b"\x30\x82\xff\xff")


def test_unknown_format():
    assert load_certs(b"hello")[2] == "unknown"


def test_utctime_and_generalized_time():
    from trustsweep.der import _time
    assert _time(0x17, b"491231235959Z").year == 2049
    assert _time(0x17, b"500101000000Z").year == 1950
    assert _time(0x18, b"20500101000000Z").year == 2050
