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

After the core added a shared timeout budget for connecting across multiple approved addresses, all six vulnerable, maintainer-fixed, and hardened redirect/scheme modes were rerun under Python 3.13.0. They still show the vulnerable paths reaching only the simulated internal service or temporary dummy file, while fixed and hardened paths block those cases and retain public JWKS parsing. These runs use an in-memory opener and synthetic DNS; the scheme case reads only its temporary fixture file.

The user's separate current-source clone was also checked without changing it: PyJWT 2.15.1 at commit `16231abfd1d8eab4953e8779b3017b859c88565e`. These behavior-only modes intentionally skip the tag version assertion while keeping the same redirect and file-scheme assertions:

```sh
PYTHONPATH=src python3.11 examples/pyjwt-ssrf/reproduce.py \
  --repo ../pyjwt-source --mode fixed-current
PYTHONPATH=src python3.11 examples/pyjwt-ssrf/reproduce.py \
  --repo ../pyjwt-source --mode fixed-current-scheme
```

Both checks passed with synthetic HTTP and a temporary dummy file. The original vulnerable and fixed-tag controls remain version-pinned.

On 2026-10-20, the tagged worktrees and current clone were re-evaluated from the user's `pyjwt-source` checkout. All 10 phases passed in 9.642 seconds: the vulnerable and fixed upstream test subsets, eight vulnerable/fixed/hardened behavior controls, and both current-source controls. The run used the existing LangChain Python 3.11 environment directly; no dependencies were installed. Its exact commands and phase results are recorded in [`results/continued-upload-limit-20261020/`](results/continued-upload-limit-20261020/). The earlier run is retained in [`results/user-source-clone-poetry311-20261020/`](results/user-source-clone-poetry311-20261020/); a separate attempt with system Python 3.11, which lacks pytest, is retained in [`results/user-source-clone-20261020/`](results/user-source-clone-20261020/) to document that environment limitation.

## Repeatable evaluation

With pytest and PyJWT's test dependencies already available, run the source controls and focused upstream tests together:

```sh
PYTHONPATH=src /path/to/python-with-pytest examples/pyjwt-ssrf/run_eval.py \
  --vulnerable-redirect ../pyjwt-2.13.0 \
  --vulnerable-scheme ../pyjwt-2.12.1 \
  --fixed-redirect ../pyjwt-2.14.0 \
  --fixed-scheme ../pyjwt-2.13.0 \
  --current-upstream ../pyjwt-source \
  --output-dir examples/pyjwt-ssrf/results/ip-policy-recheck-20261020
```

The runner performs no installation. It records source commits, per-phase commands, outcomes, and elapsed time. After the Safe Egress connection-fallback and shared timeout-budget changes, the Python 3.11 rerun passed all 10 phases in 9.641 seconds: 29 upstream tests on 2.13.0, 37 on 2.14.0 after deselecting the test that opens a loopback listener, and redirect and scheme controls on the current 2.15.1 checkout. It used the existing LangChain Poetry environment; no dependencies were installed. All SSRF controls use in-memory HTTP; the only file read is a temporary dummy fixture. See the [latest report and phase results](results/connect-budget-current/); the earlier exact-IP-only run remains in [`results/exact-ip-only-20261020/`](results/exact-ip-only-20261020/).

`safe_client.py` is an application integration example, not a replacement package for PyJWT. PyJWT does not expose a transport injection point, so an application that wants destination checks must route `fetch_data()` through a policy-enforcing opener or use an equivalent controlled wrapper. The redirect advisory requires an attacker-influenced redirect from the configured JWKS endpoint; this test supplies that redirect directly through its controlled fixture. The tests do not simulate JWT verification or key-poisoning consequences.

## Environment

Use Python 3.11 or later. No PyJWT installation is required. The script imports each source checkout directly from its `jwt/` package, plus the Safe Egress source tree through `PYTHONPATH`. It uses only Python's standard library and the checked-out PyJWT source. The fixture contains a dummy Authorization header and dummy key-set JSON; it contacts no public or internal network service. Use `python3.11` explicitly if `python3` points to an older interpreter.
