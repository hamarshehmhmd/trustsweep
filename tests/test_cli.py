import json
import subprocess
import sys
import os

import pytest

from trustsweep.cli import main
from conftest import fixture_path, pem


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_scan_table(capsys, fakeroot):
    code, out, _ = run(capsys, "scan", "--root", str(fakeroot))
    assert code == 0
    assert "python-certifi" in out and "java" in out and "system" in out
    assert "4 trust stores" in out and "stores disagree (2-4 certs each)" in out


def test_scan_json(capsys, fakeroot):
    code, out, _ = run(capsys, "scan", "--root", str(fakeroot), "--json")
    data = json.loads(out)
    system = next(b for b in data["bundles"] if b["kind"] == "system")
    assert system["certs"] == 4 and system["expired"] == 1


def test_scan_kind_filter(capsys, fakeroot):
    _, out, _ = run(capsys, "scan", "--root", str(fakeroot), "--json", "--kind", "java")
    assert [b["kind"] for b in json.loads(out)["bundles"]] == ["java"]


def test_find_by_name(capsys, fakeroot):
    code, out, _ = run(capsys, "find", "acme corp", "--root", str(fakeroot))
    assert code == 0
    assert "Acme Corp Root CA" in out and "present in 2 of 4 trust stores" in out


def test_find_by_file_shows_missing(capsys, fakeroot):
    code, out, _ = run(capsys, "find", fixture_path("corp-root.pem"), "--root", str(fakeroot), "--json")
    data = json.loads(out)["certificates"][0]
    assert sorted(data["missing_from"]) == [
        "/app/venv/lib/python3.12/site-packages/certifi/cacert.pem",
        "/usr/lib/jvm/java-21/lib/security/cacerts",
    ]


def test_find_by_fingerprint_prefix(capsys, fakeroot):
    from trustsweep.der import load_certs
    fp = load_certs(pem("shady-root.pem").encode())[0][0].fingerprint[:23]  # with colons
    code, out, _ = run(capsys, "find", fp, "--root", str(fakeroot))
    assert code == 0 and "Shady Trust Root R1" in out and "present in 1 of 4" in out


def test_find_nothing(capsys, fakeroot):
    code, out, _ = run(capsys, "find", "no such ca", "--root", str(fakeroot))
    assert code == 1 and "No certificate matching" in out


def test_check_require_fails_with_hints(capsys, fakeroot):
    code, out, _ = run(capsys, "check", "--require", fixture_path("corp-root.pem"), "--root", str(fakeroot))
    assert code == 1
    assert "2 of 4 trust stores fail" in out
    assert "REQUESTS_CA_BUNDLE" in out  # certifi hint
    assert "keytool -importcert" in out  # java hint


def test_check_require_passes_when_scoped(capsys, fakeroot):
    code, out, _ = run(capsys, "check", "--require", "Acme Corp Root CA", "--kind", "system",
                       "--kind", "pip-vendored", "--root", str(fakeroot))
    assert code == 0 and "all 2 trust stores pass" in out


def test_check_forbid(capsys, fakeroot):
    code, out, _ = run(capsys, "check", "--forbid", "Shady Trust", "--root", str(fakeroot), "--json")
    data = json.loads(out)
    assert code == 1 and not data["ok"]
    assert [p["kind"] for p in data["problems"]] == ["python-certifi"]
    assert "forbidden" in data["problems"][0]["problem"]


def test_check_expired_and_expiring(capsys, fakeroot):
    code, out, _ = run(capsys, "check", "--expired", "--expiring-days", "90", "--root", str(fakeroot))
    assert code == 1
    assert "1 expired certificate(s)" in out
    assert "'Soon Expiring Root' expires 2027-01-15" in out


def test_check_needs_a_rule(capsys):
    code, _, err = run(capsys, "check")
    assert code == 2 and "at least one" in err


def test_check_bad_require_file(capsys, tmp_path):
    empty = tmp_path / "empty.pem"
    empty.write_text("nothing here")
    with pytest.raises(SystemExit):
        main(["check", "--require", str(empty), "--no-search", "--no-node"])


def test_diff(capsys, tmp_path):
    a = tmp_path / "a.pem"
    b = tmp_path / "b.pem"
    a.write_text(pem("public-x1.pem") + pem("corp-root.pem"))
    b.write_text(pem("public-x1.pem") + pem("shady-root.pem"))
    code, out, _ = run(capsys, "diff", str(a), str(b))
    assert code == 1
    assert "1 in common" in out and "- Acme Corp Root CA" in out and "+ Shady Trust Root R1" in out
    code, out, _ = run(capsys, "diff", str(a), str(a), "--json")
    assert code == 0 and json.loads(out)["common"] == 2


def test_diff_missing_file(tmp_path):
    with pytest.raises(SystemExit):
        main(["diff", str(tmp_path / "x"), str(tmp_path / "y")])


def test_extra_files_in_scan(capsys, tmp_path):
    f = tmp_path / "corp-bundle.pem"
    f.write_text(pem("corp-root.pem"))
    code, out, _ = run(capsys, "scan", str(f), "--no-search", "--no-node", "--no-env", "--json")
    paths = [b["path"] for b in json.loads(out)["bundles"]]
    assert str(f) in paths


def test_color_always(capsys, fakeroot):
    _, out, _ = run(capsys, "find", "acme", "--root", str(fakeroot), "--color", "always")
    assert "\x1b[1m" in out


def test_module_entrypoint(fakeroot):
    env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
    p = subprocess.run([sys.executable, "-m", "trustsweep", "--version"], capture_output=True, text=True, env=env)
    assert p.returncode == 0 and p.stdout.startswith("trustsweep ")
