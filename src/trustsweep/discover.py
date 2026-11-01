"""Locate CA bundles: OS stores, Python (certifi, pip, botocore), Java, Node, env vars."""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field

from .der import Cert, load_certs

SYSTEM_PATHS = [
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Arch, Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora, RHEL, CentOS
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL 7+
    "/etc/ssl/ca-bundle.pem",  # openSUSE
    "/etc/ssl/cert.pem",  # Alpine, macOS, BSD
    "/usr/local/share/certs/ca-root-nss.crt",  # FreeBSD
    "/usr/local/etc/openssl/cert.pem",  # Homebrew (Intel)
    "/usr/local/etc/openssl@3/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",  # Homebrew (Apple silicon)
    "/opt/homebrew/etc/ca-certificates/cert.pem",
]

DEFAULT_SEARCH = ["~", "/usr/lib", "/usr/local/lib", "/usr/share", "/opt", "/usr/lib64"]

ENV_VARS = [
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE", "PIP_CERT",
]

SKIP_DIRS = {".git", ".hg", "proc", "sys", "dev", ".cache", "__pycache__", ".npm", ".Trash"}

# (path suffix, kind)
SUFFIX_KINDS = [
    ("/pip/_vendor/certifi/cacert.pem", "pip-vendored"),
    ("/certifi/cacert.pem", "python-certifi"),
    ("/botocore/cacert.pem", "python-botocore"),
    ("/httplib2/cacerts.txt", "python-httplib2"),
    ("/grpc/_cython/_credentials/roots.pem", "python-grpc"),
    ("/lib/security/cacerts", "java"),
    ("/jre/lib/security/cacerts", "java"),
    ("/etc/ssl/certs/java/cacerts", "java"),
    ("/curl-ca-bundle.crt", "curl"),
]

HINTS = {
    "system": "add the CA to /usr/local/share/ca-certificates/ and run update-ca-certificates (or update-ca-trust)",
    "python-certifi": "certifi ignores the OS store: set REQUESTS_CA_BUNDLE/SSL_CERT_FILE, or pip install truststore to use the OS store",
    "pip-vendored": "pip uses its own copy: pip config set global.cert <bundle>, or upgrade pip (recent versions can use the OS store)",
    "python-botocore": "set AWS_CA_BUNDLE to a bundle that contains the CA",
    "python-httplib2": "pass ca_certs= to httplib2.Http or upgrade the package",
    "python-grpc": "set GRPC_DEFAULT_SSL_ROOTS_FILE_PATH to a bundle that contains the CA",
    "java": "keytool -importcert -cacerts -alias <name> -file ca.pem (or -delete -alias <name> to remove)",
    "node-builtin": "Node ships its own roots: set NODE_EXTRA_CA_CERTS, or use node --use-system-ca on recent Node versions",
    "env": "this file is referenced by an environment variable; update it or point the variable elsewhere",
    "curl": "curl's bundled CA file: replace it with your system bundle",
    "file": "",
}


@dataclass
class Bundle:
    path: str
    kind: str
    certs: list[Cert] = field(default_factory=list)
    bad: int = 0
    fmt: str = ""
    error: str = ""
    source: str = ""

    def fingerprints(self) -> set[str]:
        return {c.sha256 for c in self.certs}

    def to_dict(self, now=None) -> dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "format": self.fmt,
            "certs": len(self.certs),
            "expired": sum(c.expired(now) for c in self.certs),
            "unparsed": self.bad,
            "error": self.error,
            "source": self.source,
        }


def classify(path: str) -> str:
    p = path.replace(os.sep, "/")
    for suffix, kind in SUFFIX_KINDS:
        if p.endswith(suffix):
            return kind
    return "file"


def load_bundle(path: str, kind: str | None = None, source: str = "", display: str | None = None) -> Bundle:
    b = Bundle(path=display or path, kind=kind or classify(path), source=source)
    try:
        if os.path.isdir(path):
            b.fmt = "dir"
            seen = set()
            for name in sorted(os.listdir(path)):
                fp = os.path.join(path, name)
                if not os.path.isfile(fp) or name.endswith((".0.tmp",)):
                    continue
                with open(fp, "rb") as fh:
                    certs, bad, _f = load_certs(fh.read())
                for c in certs:
                    if c.sha256 not in seen:
                        seen.add(c.sha256)
                        b.certs.append(c)
                b.bad += bad
        else:
            with open(path, "rb") as fh:
                b.certs, b.bad, b.fmt = load_certs(fh.read())
            if b.fmt == "unknown":
                b.error = "unrecognised format (PKCS#12 keystores are not supported yet)"
    except OSError as e:
        b.error = e.strerror or str(e)
    except ValueError as e:
        b.error = str(e)
    return b


def _walk(top: str, max_depth: int):
    top = os.path.abspath(top)
    base = top.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(top, onerror=lambda e: None):
        depth = dirpath.count(os.sep) - base
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))]
        if depth >= max_depth:
            dirnames[:] = []
        for f in filenames:
            if f in ("cacert.pem", "cacerts", "cacerts.txt", "roots.pem", "curl-ca-bundle.crt"):
                full = os.path.join(dirpath, f)
                if classify(full) != "file":
                    yield full


def node_builtin(node: str | None = None) -> Bundle | None:
    node = node or shutil.which("node")
    if not node:
        return None
    try:
        out = subprocess.run(
            [node, "-p", "process.version + '\\n' + require('tls').rootCertificates.join('\\n')"],
            capture_output=True, timeout=20, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    version, _, pem = out.partition(b"\n")
    certs, bad, fmt = load_certs(pem)
    return Bundle(path=f"node {version.decode().strip()} (built-in)", kind="node-builtin",
                  certs=certs, bad=bad, fmt="builtin", source=node)


def discover(
    root: str = "/",
    search: list[str] | None = None,
    extra: list[str] | None = None,
    env: dict | None = None,
    use_env: bool = True,
    use_node: bool = True,
    max_depth: int = 12,
) -> list[Bundle]:
    """Return every CA bundle found, deduplicated by real path."""
    root = os.path.abspath(root)
    in_root = root != "/"
    env = os.environ if env is None else env
    found: list[tuple[str, str | None, str]] = []  # (path, kind, source)

    def rooted(p: str) -> str:
        p = os.path.expanduser(p) if not in_root else p
        return os.path.join(root, p.lstrip("/")) if in_root else p

    for p in SYSTEM_PATHS:
        rp = rooted(p)
        if os.path.isfile(rp):
            found.append((rp, "system", "os"))
    if in_root:
        java_link = rooted("/etc/ssl/certs/java/cacerts")
        if os.path.isfile(java_link):
            found.append((java_link, "java", "os"))

    dirs = search if search is not None else (["/"] if in_root else DEFAULT_SEARCH)
    for d in dirs:
        rd = rooted(d) if in_root else os.path.expanduser(d)
        if os.path.isdir(rd):
            for f in _walk(rd, max_depth):
                found.append((f, None, "search"))

    if use_env and not in_root:
        for var in ENV_VARS:
            v = env.get(var)
            if v and os.path.exists(v):
                found.append((v, None if classify(v) != "file" else "env", f"${var}"))

    for p in extra or []:
        found.append((p, None, "argument"))

    bundles, seen = [], {}
    for path, kind, source in found:
        real = os.path.realpath(path)
        if real in seen:
            prev = seen[real]
            if source.startswith("$") and source not in prev.source:
                prev.source = f"{prev.source},{source}" if prev.source else source
            continue
        display = os.path.join("/", os.path.relpath(path, root)) if in_root and path.startswith(root) else path
        b = load_bundle(path, kind, source, display=display)
        seen[real] = b
        bundles.append(b)

    if use_node and not in_root:
        nb = node_builtin()
        if nb:
            bundles.append(nb)
    return bundles
