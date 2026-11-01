Subreddit: r/devops
Title: Made a small CLI to check a CA is actually in every trust store in an image

Body:
Got bitten one too many times by "we added the corp CA to the base image" and then a Python or Java service still failing TLS, because certifi and cacerts keep their own lists.

So I wrote trustsweep. Point it at a host or a `docker export`ed rootfs:

    trustsweep check --require corp-root.pem --root ./rootfs

It lists every bundle it finds (OS, certifi, pip's copy, botocore, Java cacerts, Node built-ins, env var bundles) and fails if any of them is missing the CA. Works as a CI step too.

https://github.com/hamarshehmhmd/trustsweep

I'm the author, feedback welcome, especially stores it misses.
