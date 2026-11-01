Title: Show HN: trustsweep – find every CA trust store on a box and check them all

URL: https://github.com/hamarshehmhmd/trustsweep

Text:
Every time we rolled out a new internal root CA, something broke weeks later. The OS store had it, but certifi in some venv didn't, pip had its own copy, Java had cacerts, Node had its roots compiled in.

trustsweep finds all of them (on a machine or an unpacked container image) and answers "is this CA in every store?" with `trustsweep check --require corp-root.pem`. Exit 1 if not, plus a hint for how to fix each kind.

Also does `find`, `diff` and expiry checks. Pure Python stdlib, reads PEM, DER and JKS itself. AGPL-3.0.

Doesn't read macOS Keychain or the Windows store yet. Happy to hear which stores I'm missing.
