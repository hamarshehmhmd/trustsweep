"""Build the demo 'container image' filesystem used in demo.mp4.

./rootfs gets: the real OS CA bundle of this machine plus a corporate root CA
(the fix a platform team usually applies), an unpatched copy of a real certifi
bundle in a Python venv, and a Java cacerts keystore without the corporate CA.
Usage: python demo/make_rootfs.py <dest-dir>
"""
import os
import shutil
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
from trustsweep.der import load_certs  # noqa: E402

CORP = os.path.join(HERE, "..", "tests", "fixtures", "corp-root.pem")
SYSTEM = "/etc/ssl/certs/ca-certificates.crt"
CERTIFI = [p for p in ("/usr/local/lib/python3.13/dist-packages/certifi/cacert.pem",) if os.path.exists(p)]


def write_jks(path, certs):
    out = struct.pack(">III", 0xFEEDFEED, 2, len(certs))
    for i, c in enumerate(certs):
        alias = f"ca{i}".encode()
        out += struct.pack(">I", 2) + struct.pack(">H", len(alias)) + alias + struct.pack(">Q", 0)
        out += struct.pack(">H", 5) + b"X.509" + struct.pack(">I", len(c.der)) + c.der
    out += b"\0" * 20
    with open(path, "wb") as fh:
        fh.write(out)


def main(dest):
    shutil.rmtree(dest, ignore_errors=True)
    corp = open(CORP).read()
    sysdata = open(SYSTEM).read()

    p = os.path.join(dest, "etc/ssl/certs/ca-certificates.crt")
    os.makedirs(os.path.dirname(p))
    open(p, "w").write(sysdata + "\n" + corp)

    p = os.path.join(dest, "app/.venv/lib/python3.12/site-packages/certifi/cacert.pem")
    os.makedirs(os.path.dirname(p))
    shutil.copy(CERTIFI[0] if CERTIFI else SYSTEM, p)

    p = os.path.join(dest, "usr/lib/jvm/java-21-openjdk/lib/security/cacerts")
    os.makedirs(os.path.dirname(p))
    write_jks(p, load_certs(sysdata.encode())[0])


if __name__ == "__main__":
    main(sys.argv[1])
