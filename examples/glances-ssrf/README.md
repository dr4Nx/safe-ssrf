# Glances public API SSRF case

This fixture-only case covers [CVE-2026-35587](https://github.com/advisories/GHSA-g5pq-48mj-jvw8) in the Glances IP plugin. `public_api` is passed to `ThreadPublicIpAddress`, which calls `urlopen_auth()` when credentials are configured. The [v4.5.4 change](https://github.com/nicolargo/glances/commit/d6808be66728956477cc4b544bab1acd71ac65fb) rejects non-HTTP(S) schemes, but the HTTP fetch path still accepts a loopback URL and sends its configured Basic Authorization header there.

## Source versions

- Vulnerable source: `nicolargo/glances` tag `v4.5.3`, downloaded from the official GitHub tag archive. SHA-256: `e5169d273e40740b9b13626fd566239050e36169cf678ae82329ccf0300e1767`.
- Maintainer-fixed source: tag `v4.5.4`, official GitHub tag archive. SHA-256: `a4f421c608d6c40e926c0256f915f0e820d92e5837e6b5a9eea582cf9b241c4a`.
- The archive snapshots have no Git metadata. `git ls-remote` could not resolve `github.com` in this environment, so their tag commit IDs were not independently checked here.

## Reproduce

From the Safe Egress repository root, acquire and unpack the two public source archives, then run the fixture harness:

```sh
curl -L https://github.com/nicolargo/glances/archive/refs/tags/v4.5.3.tar.gz -o /tmp/glances-v4.5.3.tar.gz
curl -L https://github.com/nicolargo/glances/archive/refs/tags/v4.5.4.tar.gz -o /tmp/glances-v4.5.4.tar.gz
shasum -a 256 /tmp/glances-v4.5.3.tar.gz /tmp/glances-v4.5.4.tar.gz
mkdir -p ../glances-v4.5.3 ../glances-v4.5.4
tar -xzf /tmp/glances-v4.5.3.tar.gz -C ../glances-v4.5.3 --strip-components=1
tar -xzf /tmp/glances-v4.5.4.tar.gz -C ../glances-v4.5.4 --strip-components=1
PYTHONPATH=src python3 examples/glances-ssrf/reproduce.py \
  --vulnerable-repo ../glances-v4.5.3 --fixed-repo ../glances-v4.5.4
```

The two printed hashes should be `e5169d273e40740b9b13626fd566239050e36169cf678ae82329ccf0300e1767` and `a4f421c608d6c40e926c0256f915f0e820d92e5837e6b5a9eea582cf9b241c4a`, respectively.

## Build check

Both local source snapshots built wheels under Python 3.11 without dependency
resolution or installation:

```sh
python3.11 -m pip wheel --no-deps --no-build-isolation \
  --wheel-dir /tmp/glances-v4.5.3-wheel ../glances-v4.5.3
python3.11 -m pip wheel --no-deps --no-build-isolation \
  --wheel-dir /tmp/glances-v4.5.4-wheel ../glances-v4.5.4
```

The evaluation report records the build results.
The complete Glances test suite was not run.

Glances' upstream `tests/test_core.py::TestGlances::test_012_ip` passed on
both source tags under Python 3.13. The test configuration sets
`public_disabled=True`, so it does not call the configured public-IP endpoint.
The focused test passed on both source tags. A Python 3.11
attempt could not import Glances because `psutil` is absent from that
environment; no dependencies were installed.

## One-command evaluation

The runner performs both local wheel builds, both focused upstream IP-plugin
tests, and the fixture evaluation. It writes exact commands, source file
hashes, wheel hashes, timings, and per-phase results. It does not install or
resolve dependencies. It compares the exercised source files with the recorded
v4.5.3/v4.5.4 hashes and exits nonzero if a source snapshot differs:

```sh
PYTHONPATH=src python3.13 examples/glances-ssrf/run_eval.py \
  --vulnerable-repo ../glances-v4.5.3 \
  --fixed-repo ../glances-v4.5.4 \
  --build-python /opt/homebrew/opt/python@3.11/bin/python3.11 \
  --test-python python3.13 \
  --output-dir examples/glances-ssrf/results/full-evaluation
```

All five phases passed in 2.539 seconds in the latest run. Both checked source
files still match their recorded hashes. See the [latest report](results/continued-20261020/evaluation.json), [phase results](results/continued-20261020/), and built wheels with their hashes under `results/continued-20261020/wheels/`. The earlier run remains in [`results/full-evaluation/`](results/full-evaluation/).
Wheel hashes vary between builds because the archive metadata includes build
timestamps; the report records each exact artifact hash.

The script executes the source versions' `IpPlugin.__init__`,
`ThreadPublicIpAddress` constructor and `_fetch_public_ip_info()`, and the actual
`urlopen_auth()` helper. It stubs Glances' base plugin and makes thread start
synchronous. `urllib.request.urlopen` is replaced with a fixture in the
vulnerable and fixed controls. The Safe Egress companion uses
`SafeUrllibOpener` and a synthetic public DNS answer; its `_send` is replaced
with in-memory responses. No sockets or live URLs are used.

[`safe_integration.py`](safe_integration.py) contains the reusable adapter
substitution. In a Glances integration, bind the returned class to the
`ThreadPublicIpAddress` name imported by the IP plugin:

```python
from glances.plugins.ip import ThreadPublicIpAddress as OriginalPublicIpThread
from safe_egress import FetchPolicy
from safe_integration import SafePublicIpFetcher, make_safe_thread_class

policy = FetchPolicy(
    allowed_hosts=frozenset({"ipv4.ipleak.net"}),
    allowed_ports=frozenset({443}),
)
ThreadPublicIpAddress = make_safe_thread_class(
    OriginalPublicIpThread, SafePublicIpFetcher(policy=policy)
)
```

Use an exact allowlist from trusted configuration if the endpoint is changed.
Do not derive the allowlist from the same caller-controlled URL. The harness
also verifies `SafePublicIpFetcher` refuses the broad default policy, private
IP exceptions, and policies that permit ports other than 443.

The companion is HTTPS-only because this request can carry Basic credentials;
it rejects a plain-HTTP downgrade even when the hostname is allowlisted.

Expected results: v4.5.3 and v4.5.4 both contact the simulated loopback service
and send only dummy Basic credentials; v4.5.4 disables a `file://` URL. The
vulnerable path also sends its dummy credentials to an attacker-controlled
public fixture host. Safe Egress rejects loopback, that untrusted host, a
plain-HTTP downgrade, and a public-to-loopback redirect; it still parses JSON
from the allowlisted HTTPS endpoint.

The hardened example configures `allowed_hosts={"ipv4.ipleak.net"}` and port
443 because Glances' default public IP endpoint is that host. Its policy has no
private-IP exceptions. This allowlist must come from trusted application
configuration, independently of an attacker-controlled `public_api` value. A
global-routability-only policy would still permit a configured attacker-owned
public server to receive the Basic credentials.

This is a source-path reproduction, not a full Glances installation or plugin
test suite. Framework initialization and background scheduling are stubbed;
the actual plugin and request method bodies are run. The complete local report
is [`results/evaluation.json`](results/evaluation.json).
