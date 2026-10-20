# PyJWT JWKS SSRF cases

This fixture-only source-path reproduction covers two `PyJWKClient` advisories: [CVE-2026-102267](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-9v7f-9g4p-ffgj) for redirects to an unchecked host, and [CVE-2026-48522](https://github.com/advisories/GHSA-993g-76c3-p5m4) for accepting non-HTTP schemes such as `file://`. The test uses a dummy bearer value, a temporary dummy JWKS file, and a synthetic loopback service.

## Revisions

- Redirect case vulnerable: PyJWT 2.13.0, tag commit `7144e4534c34810f4525dc4578a32addd8212cff`.
- Redirect case fixed: PyJWT 2.14.0, peeled tag commit `c6fe464b356ff4b1ebc9ba62172d331a40aa27df`.
- Redirect fix commit: `0a795b8e1f6ef08f634aa7086fc41cc6d5ce3e56`. The fixed client creates an opener with a redirect handler that refuses redirects.
- Scheme case vulnerable: PyJWT 2.12.1, tag commit `a4e1a3d1218b01c5806420b8f16d9308ac4adc30`.
- Scheme case fixed: PyJWT 2.13.0, tag commit `7144e4534c34810f4525dc4578a32addd8212cff`. The fixed client rejects any URI whose scheme is not HTTP or HTTPS.

## Reproduce

From the Safe Egress repository root, with the three source worktrees next to it:

```sh
PYTHONPATH=src python3.11 examples/pyjwt-ssrf/reproduce.py \
  --repo ../pyjwt-2.13.0 --mode vulnerable
PYTHONPATH=src python3.11 examples/pyjwt-ssrf/reproduce.py \
  --repo ../pyjwt-2.14.0 --mode fixed
PYTHONPATH=src python3.11 examples/pyjwt-ssrf/reproduce.py \
  --repo ../pyjwt-2.13.0 --mode hardened
PYTHONPATH=src python3.11 examples/pyjwt-ssrf/reproduce.py \
  --repo ../pyjwt-2.12.1 --mode vulnerable-scheme
PYTHONPATH=src python3.11 examples/pyjwt-ssrf/reproduce.py \
  --repo ../pyjwt-2.13.0 --mode fixed-scheme
PYTHONPATH=src python3.11 examples/pyjwt-ssrf/reproduce.py \
  --repo ../pyjwt-2.12.1 --mode hardened-scheme
```

The redirect fixture replaces only HTTP handling. It runs PyJWT's actual `PyJWKClient.fetch_data()` and urllib's actual redirect/error processing with an in-memory `OpenerDirector`; it opens no sockets. The vulnerable control follows a public fixture redirect to `http://127.0.0.1/internal-status` and receives dummy internal JSON, including the dummy Authorization header. The fixed release refuses the redirect before a second request. The hardened companion in `safe_client.py` subclasses PyJWT's client and routes fetches through `SafeUrllibOpener`, which rejects the loopback hop. Both fixed and hardened modes fetch and parse the public JWKS fixture.

The scheme fixture uses PyJWT 2.12.1's actual `PyJWKClient.fetch_data()` to read only a temporary file created by the test. PyJWT 2.13.0 rejects that URI at construction, and the Safe Egress integration rejects it at fetch time. Both still parse the public HTTP JWKS fixture. The temporary file contains no real data.

All six modes passed locally under Python 3.13.0. The captured outputs and exact commands are in [`results/evaluation-python313.json`](results/evaluation-python313.json).

`safe_client.py` is an application integration example, not a replacement package for PyJWT. PyJWT does not expose a transport injection point, so an application that wants destination checks must route `fetch_data()` through a policy-enforcing opener or use an equivalent controlled wrapper. The redirect advisory requires an attacker-influenced redirect from the configured JWKS endpoint; this test supplies that redirect directly through its controlled fixture. The tests do not simulate JWT verification or key-poisoning consequences.

## Environment

Use Python 3.11 or later. No PyJWT installation is required. The script imports each source checkout directly from its `jwt/` package, plus the Safe Egress source tree through `PYTHONPATH`. It uses only Python's standard library and the checked-out PyJWT source. The fixture contains a dummy Authorization header and dummy key-set JSON; it contacts no public or internal network service. Use `python3.11` explicitly if `python3` points to an older interpreter.
