Subreddit: r/sysadmin
Title: Tool to find all the CA bundles hiding on a server

Body:
If you've ever done update-ca-certificates and still had Python or Java complain about the cert chain, it's because they ship their own CA lists.

trustsweep finds them all and shows which ones have your root and which don't:

    trustsweep find corp-root.pem
    trustsweep check --expired --expiring-days 90

No dependencies, just Python 3.9+. https://github.com/hamarshehmhmd/trustsweep

(I built it, so tell me what's broken.)
