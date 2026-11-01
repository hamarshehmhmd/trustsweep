"""trustsweep command line interface."""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys

from . import __version__
from .der import Cert, load_certs
from .discover import HINTS, Bundle, discover, load_bundle

GREEN, RED, YELLOW, BOLD, DIM, RESET = "\x1b[32m", "\x1b[31m", "\x1b[33m", "\x1b[1m", "\x1b[2m", "\x1b[0m"


class Out:
    def __init__(self, color: bool):
        self.color = color

    def c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def p(self, text: str = "") -> None:
        print(text)


def _now() -> _dt.datetime:
    fixed = os.environ.get("TRUSTSWEEP_NOW")
    if fixed:
        return _dt.datetime.fromisoformat(fixed).replace(tzinfo=_dt.timezone.utc)
    return _dt.datetime.now(_dt.timezone.utc)


# ---------------------------------------------------------------- queries

_HEX = re.compile(r"^[0-9a-fA-F:]{8,}$")


class Query:
    """A certificate selector: a PEM/DER file, a SHA-256 fingerprint (prefix) or a name substring."""

    def __init__(self, text: str):
        self.text = text
        self.fps: set[str] = set()
        self.certs: list[Cert] = []
        self.kind = "name"
        if os.path.isfile(text):
            with open(text, "rb") as fh:
                certs, _bad, _fmt = load_certs(fh.read())
            if not certs:
                raise SystemExit(f"trustsweep: no certificates found in {text}")
            self.kind = "file"
            self.certs = certs
            self.fps = {c.sha256 for c in certs}
        elif _HEX.match(text) and len(text.replace(":", "")) >= 8:
            self.kind = "fingerprint"
            self.prefix = text.replace(":", "").lower()
        else:
            self.needle = text.lower()

    def matches(self, cert: Cert) -> bool:
        if self.kind == "file":
            return cert.sha256 in self.fps
        if self.kind == "fingerprint":
            return cert.sha256.startswith(self.prefix)
        return self.needle in cert.subject_str.lower()

    def label(self) -> str:
        if self.kind == "file" and len(self.certs) == 1:
            return self.certs[0].common_name or self.text
        return self.text


# ---------------------------------------------------------------- helpers

def _collect(args) -> list[Bundle]:
    search = None
    if args.path:
        search = list(args.path)
    elif args.no_search:
        search = []
    bundles = discover(
        root=args.root, search=search, extra=getattr(args, "files", None) or [],
        use_env=not args.no_env, use_node=not args.no_node, max_depth=args.max_depth,
    )
    if args.kind:
        kinds = set(args.kind)
        bundles = [b for b in bundles if b.kind in kinds]
    return bundles


def _short(path: str, width: int = 64) -> str:
    home = os.path.expanduser("~")
    if path.startswith(home + os.sep):
        path = "~" + path[len(home):]
    return path if len(path) <= width else "…" + path[-(width - 1):]


def _date(d: _dt.datetime) -> str:
    return d.strftime("%Y-%m-%d")


# ---------------------------------------------------------------- commands

def cmd_scan(args, o: Out) -> int:
    now = _now()
    bundles = _collect(args)
    if args.json:
        print(json.dumps({"bundles": [b.to_dict(now) for b in bundles]}, indent=2))
        return 0
    if not bundles:
        o.p("No CA bundles found.")
        return 0
    o.p(o.c(BOLD, f"{'KIND':<16} {'CERTS':>5} {'EXPIRED':>7}  PATH"))
    for b in bundles:
        exp = sum(c.expired(now) for c in b.certs)
        exp_s = o.c(YELLOW, f"{exp:>7}") if exp else f"{exp:>7}"
        extra = f"  {o.c(DIM, b.source)}" if b.source.startswith("$") else ""
        if b.error:
            extra += "  " + o.c(RED, b.error)
        o.p(f"{b.kind:<16} {len(b.certs):>5} {exp_s}  {_short(b.path)}{extra}")
    counts = {len(b.certs) for b in bundles if b.certs}
    uniq = len({fp for b in bundles for fp in b.fingerprints()})
    o.p()
    o.p(f"{len(bundles)} trust stores, {uniq} distinct certificates"
        + (f", stores disagree ({min(counts)}-{max(counts)} certs each)" if len(counts) > 1 else ""))
    return 0


def _matches(bundles: list[Bundle], q: Query) -> dict[str, Cert]:
    found: dict[str, Cert] = {c.sha256: c for c in q.certs}
    for b in bundles:
        for c in b.certs:
            if q.matches(c):
                found.setdefault(c.sha256, c)
    return found


def cmd_find(args, o: Out) -> int:
    now = _now()
    q = Query(args.query)
    bundles = _collect(args)
    certs = _matches(bundles, q)
    if args.json:
        print(json.dumps({
            "query": args.query,
            "certificates": [{
                "subject": c.subject_str, "sha256": c.sha256, "not_after": c.not_after.isoformat(),
                "expired": c.expired(now),
                "present_in": [b.path for b in bundles if c.sha256 in b.fingerprints()],
                "missing_from": [b.path for b in bundles if c.sha256 not in b.fingerprints()],
            } for c in certs.values()],
        }, indent=2))
        return 0 if certs else 1
    if not certs:
        o.p(f"No certificate matching {args.query!r} in {len(bundles)} trust stores.")
        return 1
    for c in sorted(certs.values(), key=lambda c: c.subject_str):
        state = o.c(RED, "EXPIRED") if c.expired(now) else "valid"
        o.p(o.c(BOLD, c.common_name or c.subject_str))
        o.p(f"  sha256 {c.fingerprint[:47]}…  expires {_date(c.not_after)} ({state})")
        have = [b for b in bundles if c.sha256 in b.fingerprints()]
        o.p(f"  present in {len(have)} of {len(bundles)} trust stores")
        for b in bundles:
            mark = o.c(GREEN, "  ✓") if b in have else o.c(DIM, "  ·")
            o.p(f"{mark} {b.kind:<16} {_short(b.path)}")
        o.p()
    return 0


def cmd_check(args, o: Out) -> int:
    now = _now()
    bundles = _collect(args)
    problems: list[tuple[Bundle | None, str]] = []
    for text in args.require or []:
        q = Query(text)
        for b in bundles:
            if b.error or not b.certs:
                continue
            if not any(q.matches(c) for c in b.certs) and not (q.kind == "file" and q.fps <= b.fingerprints()):
                problems.append((b, f"missing required CA {q.label()!r}"))
            elif q.kind == "file" and not q.fps <= b.fingerprints():
                problems.append((b, f"missing part of required CA file {q.text!r}"))
    for text in args.forbid or []:
        q = Query(text)
        for b in bundles:
            hits = [c for c in b.certs if q.matches(c)]
            for c in hits:
                problems.append((b, f"contains forbidden CA {c.common_name!r} ({c.sha256[:16]})"))
    if args.expired:
        for b in bundles:
            n = sum(c.expired(now) for c in b.certs)
            if n:
                problems.append((b, f"{n} expired certificate(s)"))
    if args.expiring_days:
        for b in bundles:
            soon = [c for c in b.certs if c.expires_within(args.expiring_days, now)]
            for c in soon:
                problems.append((b, f"{c.common_name!r} expires {_date(c.not_after)}"))
    for b in bundles:
        if b.error:
            problems.append((b, f"could not read: {b.error}"))

    if args.json:
        print(json.dumps({
            "ok": not problems, "stores_checked": len(bundles),
            "problems": [{"path": b.path if b else None, "kind": b.kind if b else None, "problem": msg,
                          "hint": HINTS.get(b.kind, "") if b else ""} for b, msg in problems],
        }, indent=2))
        return 1 if problems else 0
    if not problems:
        o.p(o.c(GREEN, f"✓ all {len(bundles)} trust stores pass"))
        return 0
    groups: dict[int, tuple[Bundle, list[str]]] = {}
    for b, msg in problems:
        groups.setdefault(id(b), (b, []))[1].append(msg)
    o.p(o.c(RED, f"✗ {len(groups)} of {len(bundles)} trust stores fail"))
    for b, msgs in groups.values():
        o.p(f"\n  {o.c(BOLD, b.kind)}  {_short(b.path, 70)}")
        for msg in msgs:
            o.p(f"    {o.c(RED, '✗')} {msg}")
        hint = HINTS.get(b.kind, "")
        if hint:
            o.p(f"      {o.c(DIM, 'fix: ' + hint)}")
    return 1


def cmd_diff(args, o: Out) -> int:
    def get(spec: str) -> Bundle:
        if spec == "node":
            from .discover import node_builtin
            nb = node_builtin()
            if not nb:
                raise SystemExit("trustsweep: node not found on PATH")
            return nb
        if spec == "system":
            from .discover import SYSTEM_PATHS
            for p in SYSTEM_PATHS:
                if os.path.isfile(p):
                    return load_bundle(p, "system")
            raise SystemExit("trustsweep: no system bundle found")
        if not os.path.exists(spec):
            raise SystemExit(f"trustsweep: {spec}: no such file")
        return load_bundle(spec)

    a, b = get(args.a), get(args.b)
    for x in (a, b):
        if x.error:
            raise SystemExit(f"trustsweep: {x.path}: {x.error}")
    fa, fb = a.fingerprints(), b.fingerprints()
    only_a = sorted((c for c in a.certs if c.sha256 not in fb), key=lambda c: c.common_name.lower())
    only_b = sorted((c for c in b.certs if c.sha256 not in fa), key=lambda c: c.common_name.lower())
    if args.json:
        conv = lambda cs: [{"subject": c.subject_str, "sha256": c.sha256} for c in cs]
        print(json.dumps({"a": a.path, "b": b.path, "only_in_a": conv(only_a), "only_in_b": conv(only_b),
                          "common": len(fa & fb)}, indent=2))
        return 1 if (only_a or only_b) else 0
    o.p(f"{o.c(BOLD, 'A')} {_short(a.path, 70)} ({len(a.certs)} certs)")
    o.p(f"{o.c(BOLD, 'B')} {_short(b.path, 70)} ({len(b.certs)} certs)")
    o.p(f"{len(fa & fb)} in common")
    for title, cs, sign, col in (("only in A", only_a, "-", RED), ("only in B", only_b, "+", GREEN)):
        if cs:
            o.p(f"\n{title} ({len(cs)}):")
            for c in cs:
                o.p(o.c(col, f"  {sign} {c.common_name or c.subject_str}") + o.c(DIM, f"  {c.sha256[:16]}"))
    return 1 if (only_a or only_b) else 0


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group("where to look")
    g.add_argument("--root", default="/", metavar="DIR",
                   help="scan a filesystem tree instead of this machine (e.g. an exported container image)")
    g.add_argument("--path", action="append", metavar="DIR",
                   help="directory to search for bundled CA files (repeatable; default: ~, /usr/lib, /usr/local/lib, /usr/share, /opt)")
    g.add_argument("--no-search", action="store_true", help="only check OS stores, env vars and node")
    g.add_argument("--no-env", action="store_true", help="ignore SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS, ...")
    g.add_argument("--no-node", action="store_true", help="skip Node.js built-in roots")
    g.add_argument("--kind", action="append", metavar="KIND",
                   help="only these store kinds (system, python-certifi, pip-vendored, java, node-builtin, ...)")
    g.add_argument("--max-depth", type=int, default=12, help=argparse.SUPPRESS)
    common.add_argument("--json", action="store_true", help="machine-readable output")
    common.add_argument("--color", choices=["auto", "always", "never"], default="auto")

    p = argparse.ArgumentParser(
        prog="trustsweep",
        description="Find every CA trust store (OS, Python certifi/pip, Java cacerts, Node, env vars) "
                    "and check them all at once.",
    )
    p.add_argument("--version", action="version", version=f"trustsweep {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", parents=[common], help="list every trust store found")
    s.add_argument("files", nargs="*", help="extra bundle files or directories to include")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("find", parents=[common], help="show which trust stores contain a CA")
    f.add_argument("query", help="CA name substring, SHA-256 fingerprint (prefix) or PEM/DER file")
    f.set_defaults(func=cmd_find)

    c = sub.add_parser("check", parents=[common], help="fail (exit 1) if any trust store breaks a rule; for CI")
    c.add_argument("--require", action="append", metavar="CA", help="every store must contain this CA (file, fingerprint or name)")
    c.add_argument("--forbid", action="append", metavar="CA", help="no store may contain this CA (e.g. a distrusted root)")
    c.add_argument("--expired", action="store_true", help="fail on expired certificates")
    c.add_argument("--expiring-days", type=int, metavar="N", help="fail on certificates expiring within N days")
    c.set_defaults(func=cmd_check)

    d = sub.add_parser("diff", parents=[common], help="compare two bundles ('system', 'node' or a path)")
    d.add_argument("a")
    d.add_argument("b")
    d.set_defaults(func=cmd_diff)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "check" and not (args.require or args.forbid or args.expired or args.expiring_days):
        print("trustsweep check: give at least one of --require, --forbid, --expired, --expiring-days", file=sys.stderr)
        return 2
    color = args.color == "always" or (args.color == "auto" and sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
    try:
        return args.func(args, Out(color))
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
