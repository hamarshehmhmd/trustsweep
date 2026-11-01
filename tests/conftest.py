import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from trustsweep.der import load_certs  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture_path(name):
    return os.path.join(FIX, name)


def pem(name):
    with open(fixture_path(name)) as fh:
        return fh.read()


def write_jks(path, pems, version=2):
    """Write a minimal JKS keystore with trusted-cert entries (password checksum is not validated)."""
    out = struct.pack(">III", 0xFEEDFEED, version, len(pems))
    for i, p in enumerate(pems):
        der = load_certs(p.encode())[0][0].der
        alias = f"ca{i}".encode()
        out += struct.pack(">I", 2) + struct.pack(">H", len(alias)) + alias + struct.pack(">Q", 0)
        if version == 2:
            out += struct.pack(">H", 5) + b"X.509"
        out += struct.pack(">I", len(der)) + der
    out += b"\0" * 20  # keyed SHA-1 digest (ignored)
    with open(path, "wb") as fh:
        fh.write(out)


@pytest.fixture
def fakeroot(tmp_path):
    """A container-like filesystem with several disagreeing trust stores."""
    r = tmp_path / "rootfs"
    sysb = r / "etc/ssl/certs/ca-certificates.crt"
    sysb.parent.mkdir(parents=True)
    sysb.write_text(pem("public-x1.pem") + pem("public-x2.pem") + pem("corp-root.pem") + pem("expired-root.pem"))
    certifi = r / "app/venv/lib/python3.12/site-packages/certifi/cacert.pem"
    certifi.parent.mkdir(parents=True)
    certifi.write_text(pem("public-x1.pem") + pem("public-x2.pem") + pem("shady-root.pem"))
    pipv = r / "usr/lib/python3/dist-packages/pip/_vendor/certifi/cacert.pem"
    pipv.parent.mkdir(parents=True)
    pipv.write_text(pem("public-x1.pem") + pem("corp-root.pem") + pem("soon-root.pem"))
    java = r / "usr/lib/jvm/java-21/lib/security/cacerts"
    java.parent.mkdir(parents=True)
    write_jks(str(java), [pem("public-x1.pem"), pem("public-x2.pem")])
    # noise that must be ignored
    (r / "app/notes/cacert.pem").parent.mkdir(parents=True)
    (r / "app/notes/cacert.pem").write_text(pem("shady-root.pem"))
    return r


@pytest.fixture(autouse=True)
def fixed_now(monkeypatch):
    monkeypatch.setenv("TRUSTSWEEP_NOW", "2026-11-01T00:00:00")
    monkeypatch.setenv("NO_COLOR", "1")
