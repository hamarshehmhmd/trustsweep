import os

from trustsweep.discover import classify, discover, load_bundle, node_builtin
from conftest import fixture_path, pem


def kinds(bundles):
    return sorted((b.kind, b.path) for b in bundles)


def test_root_scan_finds_every_store(fakeroot):
    bs = discover(root=str(fakeroot), use_node=False)
    assert kinds(bs) == [
        ("java", "/usr/lib/jvm/java-21/lib/security/cacerts"),
        ("pip-vendored", "/usr/lib/python3/dist-packages/pip/_vendor/certifi/cacert.pem"),
        ("python-certifi", "/app/venv/lib/python3.12/site-packages/certifi/cacert.pem"),
        ("system", "/etc/ssl/certs/ca-certificates.crt"),
    ]
    counts = {b.kind: len(b.certs) for b in bs}
    assert counts == {"java": 2, "pip-vendored": 3, "python-certifi": 3, "system": 4}


def test_root_scan_ignores_env_and_node(fakeroot, monkeypatch, tmp_path):
    extra = tmp_path / "extra.pem"
    extra.write_text(pem("corp-root.pem"))
    monkeypatch.setenv("SSL_CERT_FILE", str(extra))
    bs = discover(root=str(fakeroot))
    assert all(b.kind != "node-builtin" and b.source != "$SSL_CERT_FILE" for b in bs)


def test_env_vars_and_dedupe(tmp_path):
    a = tmp_path / "corp.pem"
    a.write_text(pem("corp-root.pem"))
    env = {"REQUESTS_CA_BUNDLE": str(a), "SSL_CERT_FILE": str(a), "NODE_EXTRA_CA_CERTS": "/does/not/exist"}
    bs = discover(search=[], env=env, use_node=False)
    env_bundles = [b for b in bs if b.path == str(a)]
    assert len(env_bundles) == 1
    assert env_bundles[0].kind == "env"
    assert "$SSL_CERT_FILE" in env_bundles[0].source and "$REQUESTS_CA_BUNDLE" in env_bundles[0].source


def test_symlinked_bundle_counted_once(tmp_path):
    d = tmp_path / "lib/python3.12/site-packages/certifi"
    d.mkdir(parents=True)
    (d / "cacert.pem").write_text(pem("public-x1.pem"))
    link = tmp_path / "lib2/python3.12/site-packages/certifi"
    link.mkdir(parents=True)
    os.symlink(d / "cacert.pem", link / "cacert.pem")
    bs = discover(search=[str(tmp_path)], use_env=False, use_node=False)
    assert len([b for b in bs if b.kind == "python-certifi"]) == 1


def test_cert_directory(tmp_path):
    d = tmp_path / "certs"
    d.mkdir()
    (d / "a.pem").write_text(pem("public-x1.pem"))
    (d / "b.crt").write_text(pem("corp-root.pem"))
    (d / "dup.pem").write_text(pem("corp-root.pem"))
    (d / "README").write_text("not a cert")
    b = load_bundle(str(d))
    assert b.fmt == "dir" and len(b.certs) == 2


def test_missing_and_unknown_files(tmp_path):
    b = load_bundle(str(tmp_path / "nope.pem"))
    assert b.error
    junk = tmp_path / "store.p12"
    junk.write_bytes(b"\x01\x02\x03")
    assert "PKCS#12" in load_bundle(str(junk)).error


def test_classify():
    assert classify("/x/site-packages/certifi/cacert.pem") == "python-certifi"
    assert classify("/x/site-packages/pip/_vendor/certifi/cacert.pem") == "pip-vendored"
    assert classify("/x/site-packages/botocore/cacert.pem") == "python-botocore"
    assert classify("/usr/lib/jvm/x/lib/security/cacerts") == "java"
    assert classify("/random/cacert.pem") == "file"


def test_depth_limit(tmp_path):
    deep = tmp_path / "a/b/c/d/e/certifi"
    deep.mkdir(parents=True)
    (deep / "cacert.pem").write_text(pem("public-x1.pem"))
    def found(depth):
        return [b for b in discover(search=[str(tmp_path)], use_env=False, use_node=False, max_depth=depth)
                if b.source == "search"]
    assert found(2) == []
    assert len(found(12)) == 1


def test_node_builtin_missing_binary():
    assert node_builtin("/no/such/node") is None


def test_node_builtin_with_fake_node(tmp_path):
    fake = tmp_path / "node"
    body = pem("public-x1.pem").replace("\n", "\\n")
    fake.write_text(f"#!/bin/sh\nprintf 'v99.0.0\\n{body}'\n")
    fake.chmod(0o755)
    b = node_builtin(str(fake))
    assert b.path == "node v99.0.0 (built-in)" and len(b.certs) == 1 and b.kind == "node-builtin"
