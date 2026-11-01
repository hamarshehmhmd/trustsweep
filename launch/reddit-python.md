Subreddit: r/Python
Title: trustsweep: see which certifi copies on your machine are missing your company's CA

Body:
Classic one: curl works, `requests` says CERTIFICATE_VERIFY_FAILED. That's certifi using its own bundle instead of the OS one, and there's usually one per venv plus one vendored inside pip.

I made a small stdlib-only tool that finds every one of them (and Java/Node stores too) and checks them in one go:

    trustsweep check --require corp-root.pem --kind python-certifi

Wrote my own little X.509 reader so there are no deps. https://github.com/hamarshehmhmd/trustsweep

I'm the author, would love feedback.
