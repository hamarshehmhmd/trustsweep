"""Minimal, dependency-free X.509 reader.

Only what trustsweep needs: subject, issuer, validity dates and the SHA-256
fingerprint of each certificate in a PEM bundle, a DER file or a JKS keystore.
"""
from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import re
import struct
from dataclasses import dataclass, field

_OIDS = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
}

PEM_RE = re.compile(
    rb"-----BEGIN (?:TRUSTED )?CERTIFICATE-----(.+?)-----END (?:TRUSTED )?CERTIFICATE-----",
    re.S,
)


class DERError(ValueError):
    pass


def _read_tlv(data: bytes, pos: int) -> tuple[int, int, int, int]:
    """Return (tag, content_start, content_end, next_pos)."""
    if pos + 2 > len(data):
        raise DERError("truncated TLV")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise DERError("bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise DERError("truncated value")
    return tag, pos, end, end


def _children(data: bytes, start: int, end: int):
    pos = start
    while pos < end:
        tag, s, e, pos = _read_tlv(data, pos)
        yield tag, s, e


def _oid(raw: bytes) -> str:
    if not raw:
        raise DERError("empty OID")
    parts = [raw[0] // 40, raw[0] % 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return ".".join(map(str, parts))


def _string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:  # BMPString
        return raw.decode("utf-16-be", "replace")
    if tag == 0x1C:  # UniversalString
        return raw.decode("utf-32-be", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _name(data: bytes, start: int, end: int) -> list[tuple[str, str]]:
    out = []
    for _t, rs, re_ in _children(data, start, end):  # SET
        for _t2, as_, ae in _children(data, rs, re_):  # SEQUENCE
            kids = list(_children(data, as_, ae))
            if len(kids) < 2 or kids[0][0] != 0x06:
                continue
            oid = _oid(data[kids[0][1]:kids[0][2]])
            vt, vs, ve = kids[1]
            out.append((_OIDS.get(oid, oid), _string(vt, data[vs:ve])))
    return out


def _time(tag: int, raw: bytes) -> _dt.datetime:
    s = raw.decode("ascii").rstrip("Z")
    if tag == 0x17:  # UTCTime YYMMDDHHMM[SS]
        yy = int(s[:2])
        s = ("19" if yy >= 50 else "20") + s
    fmt = "%Y%m%d%H%M%S" if len(s) >= 14 else "%Y%m%d%H%M"
    return _dt.datetime.strptime(s[: 14 if len(s) >= 14 else 12], fmt).replace(tzinfo=_dt.timezone.utc)


@dataclass(frozen=True)
class Cert:
    der: bytes = field(repr=False)
    subject: tuple[tuple[str, str], ...]
    issuer: tuple[tuple[str, str], ...]
    not_before: _dt.datetime
    not_after: _dt.datetime

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def fingerprint(self) -> str:
        h = self.sha256.upper()
        return ":".join(h[i:i + 2] for i in range(0, len(h), 2))

    def _get(self, rdn, key):
        return next((v for k, v in rdn if k == key), "")

    @property
    def common_name(self) -> str:
        return self._get(self.subject, "CN") or self._get(self.subject, "OU") or self._get(self.subject, "O")

    @property
    def organization(self) -> str:
        return self._get(self.subject, "O")

    @property
    def subject_str(self) -> str:
        return ", ".join(f"{k}={v}" for k, v in self.subject)

    def expired(self, now: _dt.datetime | None = None) -> bool:
        return self.not_after < (now or _dt.datetime.now(_dt.timezone.utc))

    def expires_within(self, days: int, now: _dt.datetime | None = None) -> bool:
        now = now or _dt.datetime.now(_dt.timezone.utc)
        return now <= self.not_after < now + _dt.timedelta(days=days)

    def pem(self) -> str:
        b = base64.b64encode(self.der).decode()
        body = "\n".join(b[i:i + 64] for i in range(0, len(b), 64))
        return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def parse_der(der: bytes) -> Cert:
    tag, s, e, nxt = _read_tlv(der, 0)
    if tag != 0x30:
        raise DERError("certificate is not a SEQUENCE")
    der = der[:nxt]
    tag, ts, te, _ = _read_tlv(der, s)  # TBSCertificate
    if tag != 0x30:
        raise DERError("tbsCertificate is not a SEQUENCE")
    kids = list(_children(der, ts, te))
    if kids and kids[0][0] == 0xA0:  # explicit version
        kids = kids[1:]
    if len(kids) < 5:
        raise DERError("tbsCertificate too short")
    _serial, _alg, issuer, validity, subject = kids[:5]
    times = list(_children(der, validity[1], validity[2]))
    if len(times) != 2:
        raise DERError("bad validity")
    return Cert(
        der=der,
        subject=tuple(_name(der, subject[1], subject[2])),
        issuer=tuple(_name(der, issuer[1], issuer[2])),
        not_before=_time(times[0][0], der[times[0][1]:times[0][2]]),
        not_after=_time(times[1][0], der[times[1][1]:times[1][2]]),
    )


def parse_pem_bundle(data: bytes) -> tuple[list[Cert], int]:
    """Return (certs, number_of_unparseable_blocks)."""
    certs, bad = [], 0
    for m in PEM_RE.finditer(data):
        try:
            der = base64.b64decode(b"".join(m.group(1).split()), validate=False)
            certs.append(parse_der(der))
        except (DERError, ValueError, binascii.Error, IndexError):
            bad += 1
    return certs, bad


JKS_MAGIC = 0xFEEDFEED


def parse_jks(data: bytes) -> tuple[list[Cert], int]:
    """Read trusted-certificate entries from a JKS keystore (no password needed)."""
    if len(data) < 12 or struct.unpack(">I", data[:4])[0] != JKS_MAGIC:
        raise DERError("not a JKS keystore")
    version, count = struct.unpack(">II", data[4:12])
    pos, certs, bad = 12, [], 0

    def utf():
        nonlocal pos
        (n,) = struct.unpack(">H", data[pos:pos + 2])
        s = data[pos + 2:pos + 2 + n].decode("utf-8", "replace")
        pos += 2 + n
        return s

    def blob():
        nonlocal pos
        (n,) = struct.unpack(">I", data[pos:pos + 4])
        b = data[pos + 4:pos + 4 + n]
        pos += 4 + n
        return b

    for _ in range(count):
        (etype,) = struct.unpack(">I", data[pos:pos + 4])
        pos += 4
        utf()  # alias
        pos += 8  # timestamp
        if etype == 2:  # trusted cert
            if version == 2:
                utf()
            der = blob()
            try:
                certs.append(parse_der(der))
            except DERError:
                bad += 1
        elif etype == 1:  # private key entry: skip key + chain
            blob()
            (n,) = struct.unpack(">I", data[pos:pos + 4])
            pos += 4
            for _c in range(n):
                if version == 2:
                    utf()
                blob()
        else:
            raise DERError(f"unknown JKS entry type {etype}")
    return certs, bad


def load_certs(data: bytes) -> tuple[list[Cert], int, str]:
    """Detect the format of ``data`` and return (certs, bad, format)."""
    if data[:4] == b"\xfe\xed\xfe\xed":
        c, b = parse_jks(data)
        return c, b, "jks"
    if b"-----BEGIN" in data:
        c, b = parse_pem_bundle(data)
        return c, b, "pem"
    if data[:1] == b"\x30":
        try:
            return [parse_der(data)], 0, "der"
        except DERError:
            pass
    return [], 0, "unknown"
