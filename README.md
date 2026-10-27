# safe-egress

A small Python prototype for fetching attacker-influenced HTTP(S) URLs while enforcing destination policy at the socket connection. The core runtime has no third-party dependencies; the Requests, HTTPX, aiohttp, urllib3, urllib, and experimental curl-cffi adapters are optional.

**Status: early prototype, not security-audited.** The core supports bounded HTTP requests over direct sockets; the client adapters cover common URL-fetching call sites but are not drop-in replacements for every client feature. The tests use mocked DNS and transport responses; they do not prove behavior against every operating system resolver or network stack.

## Example

```python
from safe_egress import FetchPolicy, SafeFetcher

fetcher = SafeFetcher(
    FetchPolicy(
        allowed_ports=frozenset({80, 443}),
        max_redirects=3,
        max_response_bytes=2_000_000,
        timeout_seconds=4.0,
    )
)

response = fetcher.get(user_supplied_url)
if response.status_code == 200:
    process(response.content)
```

The default policy allows globally routable unicast destinations on ports 80 and 443. It rejects private, loopback, link-local, multicast, reserved, and special-use destinations. Multicast remains denied even if its address is added to `allowed_ips`. The policy supplements Python's `ipaddress` tables for several newer IANA special-purpose assignments; see the [threat model](docs/threat-model.md). Every DNS answer must pass the policy; the fetcher dials a checked numeric address and tries the next checked answer if connection setup fails before any HTTP request is sent. It does not retry write or response failures. HTTPS still uses the original hostname for SNI and certificate verification. Redirects are followed manually and revalidated one hop at a time.

For an integration that intentionally uses a private service with a known address, configure both the exact hostname and exact IP:

```python
policy = FetchPolicy(
    allowed_hosts=frozenset({"files.example.net", "internal-files.corp.example"}),
    allowed_ips=frozenset({"10.20.30.40"}),
)
```

Every DNS answer must be globally routable or explicitly listed in `allowed_ips`; multicast addresses are rejected even when listed. A changed or mixed private answer is rejected unless that specific IP is listed. A host allowlist never overrides address checks; private destinations are allowed only by exact IP. `allowed_ips` is not tied to a hostname: without `allowed_hosts`, any URL hostname that resolves to a listed IP can use that address, with its own HTTP Host authority. Pair the exact IP with an exact hostname allowlist when a particular virtual host or service is intended. Update the IP when the trusted service moves, and avoid broad suffix matching.

For a client with a transport Safe Egress does not implement, `SafeFetcher.validate_destination(url, policy=...)` returns the normalized host, port, request target, and all policy-approved numeric addresses without connecting. The adapter must pin its actual socket or resolver to one of those addresses on every redirect hop. Passing the original URL to an ordinary client after validation is unsafe because that client can resolve the hostname again. The [`ValidatedDestination` API](docs/threat-model.md#validated-destination-api) documents this contract.

## Development checks

Run the dependency-free core suite:

```sh
PYTHONPATH=src python3.11 -m unittest discover -v
```

Most tests use controlled resolver records and in-memory transports. A core socket test and an adapter utility test bind an ephemeral loopback port when the environment permits it; otherwise they skip with the bind error. The adapter suite also has a denial test that stubs socket connection methods and verifies Requests, sync and async HTTPX, aiohttp, urllib, and urllib3 reject loopback without trying to connect. No test contacts an external system. Adapter tests are skipped when their optional clients are absent. To run the complete adapter suite, provision the optional dependencies first, then run the same command:

```sh
python3.11 -m pip install -e '.[requests,httpx,aiohttp,urllib3]'
PYTHONPATH=src python3.11 -m unittest discover -v
```

The optional install requires package access; no package download is needed for the core suite. Actual OS resolver and socket behavior still need a separately controlled integration environment.

To use the `pytest` command shown below, install its optional test dependency too:

```sh
python3.11 -m pip install -e '.[test,requests,httpx,aiohttp,urllib3]'
```

The complete library suite was run in an existing Python 3.11.17 environment with Requests 2.32.3, HTTPX 0.27.0, aiohttp 3.9.5, urllib3 2.2.2, and pytest 7.4.4. curl-cffi is absent; its adapter tests use fake Session and Curl boundaries and do not validate the native client runtime. Install the experimental adapter's reviewed version with `python3.11 -m pip install -e '.[curl-cffi]'`; the optional extra pins curl-cffi 0.15.0.

```sh
PYTHONPATH=src python3.11 -m pytest -q
```

Pytest discovery is scoped to the library suite so it does not collect grader tests under `examples/`. The current Python 3.11 source run reports **189 passed, 2 skipped**; `unittest discover` reports **190 tests, 2 skipped**. The skipped checks bind a real loopback listener: one exercises the core fetcher and one exercises allowed local-resource fetching through the adapters. This sandbox denies loopback binds, so those checks skip here; adapter denial and parser-confusion tests pass with socket connections stubbed and asserted unused. The curl-cffi adapter tests use a fake session API; its native curl-cffi runtime still needs validation. No dependencies were installed for these runs; they used the existing Python 3.11 environment.

The latest source wheel was rebuilt with the existing Python 3.13 setuptools backend and installed into a temporary target with `pip --no-index --no-deps`. All 14 packaged Python modules match the current source tree byte-for-byte. The installed-wheel suite reports **189 passed, 2 skipped** under pytest and **190 tests, 2 skipped** under unittest. See the [wheel](results/package-wheel-active-goal-20261020/safe_egress-0.1.0-py3-none-any.whl). Its SHA-256 is `63f389e761af82c84cf385e35cdb95914815d0107a6ea4892bf3c97e119d0bac`. The current system Python 3.11 is missing `setuptools.build_meta`, so wheel building there fails; Python 3.13 built it without installing packages.

Rebuild the wheel from the repository root with:

```sh
python3.13 -m pip wheel . --no-deps --no-build-isolation \
  --wheel-dir results/package-wheel-active-goal-20261020
```

Wheel metadata can vary between builds; use the hash in the evaluation report to identify the artifact actually tested.

The current source and installed wheel both pass `unittest discover`: 190 tests, 2 skipped each.

The latest source-matching wheel matrix passed **17/17 phases** in 2.962 seconds using Python 3.13 with urllib3 2.3.0. Its wheel SHA-256 is `63f389e761af82c84cf385e35cdb95914815d0107a6ea4892bf3c97e119d0bac`; all 14 packaged Python modules match the current source. The report records commands, source revisions or tree hashes, import origins, Python/platform details, client dependency versions and timings. Rerun the matrix with [`scripts/evaluate_installed_wheel_cves.py`](scripts/evaluate_installed_wheel_cves.py). It expects the local CVE worktrees and dependencies to already exist; it never installs packages. The [latest matrix report](results/installed-wheel-cve-matrix-active-goal-20261020/evaluation.json) has the complete record. The Crawlee phase sends URLs queued by the vulnerable sitemap loader through a custom Safe Egress `HttpClient`, tests it against the actual abstract base API from both vulnerable v1.6.3 and fixed v1.7.0, and exercises `send_request()` and `crawl()`; it also checks exact-IP private-service allowlisting, `CookieJar` session isolation, cross-origin cookie stripping, and policy/request timeouts. The matrix covers Requests (Local Deep Research and Kolibri), HTTPX (Nanobot and Crawlee), aiohttp (LangChain Community), urllib (PyJWT and Glances), and urllib3. It does not include the curl-cffi runtime case because that dependency is unavailable. All fixtures use synthetic DNS and in-memory responses; they do not open sockets or contact external systems.

```sh
python3.13 scripts/evaluate_installed_wheel_cves.py \
  --python311 /path/to/python311-with-client-test-dependencies \
  --python313 /path/to/python313-with-urllib3-2.3.0 \
  --wheel-site /path/to/installed-safe-egress-target \
  --wheel /path/to/safe_egress-0.1.0-py3-none-any.whl \
  --output-dir results/installed-wheel-cve-matrix
```

In the available Python 3.13 environment, the existing neighboring virtualenv ran **80 core tests**; **67 adapter tests** were skipped because Requests, aiohttp, and urllib3 are missing there, and the loopback socket test skipped because binds are denied. Python 3.14.8 also ran `unittest discover`: **58 passed, 96 skipped** because optional client dependencies are absent. The stdlib urllib tests ran without the ResourceWarnings previously seen in that environment. No dependencies were installed for either check.

A separate existing Python 3.13.0 interpreter with HTTPX 0.28.1 and urllib3 2.3.0 reran the focused adapter suites: **22 HTTPX tests and 12 urllib3 tests passed** after the HTTPX parser-error mapping change. This checks newer client versions than the Python 3.11 environment and required no dependency installation.

The optional `safe-egress-audit` command inventories some common direct network calls in Python source (after installing the package; from a checkout, use `PYTHONPATH=src python3.11 -m safe_egress.audit`):

```sh
safe-egress-audit path/to/source
```

It is a heuristic sink inventory, not taint analysis or proof that SSRF is absent. It recognizes module-level calls and sessions from `requests_compat` as policy-bound; it may still miss wrapper methods, dynamic imports, custom clients, browser traffic, raw socket usage, and indirect session calls.

## Client adapters

Install only the client extras you need:

```sh
python -m pip install 'safe-egress[requests,httpx,aiohttp,urllib3]'
```

The optional [`SafeCurlCffiSession`](src/safe_egress/curl_cffi_adapter.py) is a synchronous requests-like wrapper for bounded byte requests. It pins every hop with libcurl `CURLOPT_RESOLVE`, checks the resolved peer in `OPENSOCKETFUNCTION` before creating a socket, rechecks the connected peer before HTTP, disables automatic redirects, proxies, and environment routing, strips sensitive headers across origins, and enforces a response-size cap during receipt. It creates a fresh curl-cffi session per redirect hop. It does not support async requests, WebSockets, streaming, upload forms, impersonation, custom curl options, or a persistent cookie jar; the API is intentionally smaller than curl-cffi's `Session`.

```python
from safe_egress import FetchPolicy, SafeCurlCffiSession

with SafeCurlCffiSession(policy=FetchPolicy()) as session:
    response = session.get(user_url, timeout=8)
    print(response.status_code, response.text)
```

From the repository root, create an environment for the experimental adapter when package access is available:

```sh
python3.11 -m venv /tmp/safe-egress-curl-cffi
/tmp/safe-egress-curl-cffi/bin/python -m pip install -e '.[curl-cffi]'
/tmp/safe-egress-curl-cffi/bin/python examples/cve-repros/curl-cffi/preflight.py
```

The adapter's 19 tests exercise DNS pin-rule construction, IPv4/IPv6 socket-address parsing, redirect behavior, pre-connect peer rejection, public fetches, and body bounds through a fake curl-cffi API. They pass under Python 3.11, 3.13, and 3.14. A system-libcurl preflight invokes both ctypes and standalone CFFI callbacks with `127.0.0.1:1`; the CFFI callback uses the adapter's actual sockaddr decoder and aborts before opening a socket. The real curl-cffi runtime and socket-based CVE fixture have not run because curl-cffi is absent and loopback binds are denied. See the [Python 3.11](results/curl-cffi-preflight-cffi-opensocket-python311-20261020.json), [Python 3.13](results/curl-cffi-preflight-cffi-opensocket-python313-20261020.json), and [Python 3.14](results/curl-cffi-preflight-cffi-opensocket-python314-20261020.json) preflight reports and the [CVE-2026-33752 fixture notes](examples/cve-repros/curl-cffi/README.md).

For Requests code that needs a Session:

```python
from safe_egress import FetchPolicy
from safe_egress.requests_adapter import SafeRequestsSession

with SafeRequestsSession(policy=FetchPolicy()) as session:
    response = session.get(user_url, headers={"Accept": "text/html"}, timeout=8)
    # The numeric peer Safe Egress validated and connected to.
    peer_ip = response.safe_egress_peer_ip
```

For common module-level calls, replace the Requests import with the scoped compatibility facade:

```python
import safe_egress.requests_compat as requests

response = requests.get(user_url, timeout=8)
with requests.Session() as session:
    response = session.post(upload_url, data=b"bounded body")

policy = requests.Allow("1.2.3.4", "www.mytrusted.server")
response = requests.get(user_url, policy=policy)
```

`Allow()` builds a `FetchPolicy` with exact hostname and IP entries. Listed hostnames still must resolve only to public addresses unless their specific private IP is also listed; wildcard and suffix entries are rejected. The facade provides `request`, `get`, `options`, `head`, `post`, `put`, `patch`, `delete`, `Session`, and `session()`, plus the Requests `Request`/`PreparedRequest`/`Response` types, `exceptions` namespace, and common top-level exception aliases. It is not a full Requests implementation: unsupported options such as proxies, streaming, custom TLS configuration, and multipart uploads fail closed in the adapter.

An application can supply a trusted, request-specific policy when one fetch needs a different destination set:

```python
from safe_egress import FetchPolicy
from safe_egress.requests_adapter import SafeRequestsSession

internal_files = FetchPolicy(
    allowed_hosts=frozenset({"files.internal.example"}),
    allowed_ips=frozenset({"10.20.30.40"}),
)
with SafeRequestsSession() as session:
    response = session.get(file_url, policy=internal_files)
```

The request policy replaces the session policy for that call, including on redirects. The urllib3 and urllib opener APIs also accept a trusted per-call policy:

```python
from safe_egress.urllib3_compat import PoolManager
from safe_egress.urllib_adapter import SafeUrllibOpener

with PoolManager() as http:
    response = http.request("GET", file_url, policy=internal_files)
with SafeUrllibOpener().open(file_url, policy=internal_files) as response:
    body = response.read()
```

Treat policy objects as trusted application configuration; never build one directly from request input. A request policy applies to every redirect hop. A per-request policy on `SafeRequestsSession` must use the session's configured `max_redirects`. Private destinations require exact `allowed_ips` entries, which are rechecked on every redirect.

Cross-origin redirects strip standard credentials, common API-key headers, common session or service tokens, and `Referer` (which may contain sensitive URL data), including AWS IMDSv2 and Vault/Consul token headers. Add custom secret header names to the trusted policy so they are stripped too:

```python
policy = FetchPolicy(additional_sensitive_headers=frozenset({"X-Company-Secret"}))
```

For synchronous HTTPX code:

```python
from safe_egress.httpx_adapter import SafeClient

with SafeClient() as client:
    response = client.get(user_url)
```

For asynchronous HTTPX code:

```python
from safe_egress.httpx_adapter import SafeAsyncClient

async with SafeAsyncClient(policy=FetchPolicy()) as client:
    response = await client.get(user_url)
```

HTTPX supports trusted per-request overrides through `request()`; the policy follows redirects and must use the client's configured redirect limit:

```python
with SafeClient() as client:
    response = client.request("GET", file_url, policy=internal_files)
```

For aiohttp code, create a session with the policy resolver:

```python
from safe_egress import FetchPolicy
from safe_egress.aiohttp_adapter import safe_aiohttp_session

async with safe_aiohttp_session(policy=FetchPolicy()) as session:
    async with session.get(user_url) as response:
        content = await response.read()
```

The aiohttp policy is fixed when the session is created; this adapter does not accept a per-request `policy=` override. Use separate sessions for fetches that need different trusted policies.

For code that directly uses urllib3, use the narrow request facade:

```python
from safe_egress.urllib3_adapter import SafeUrllib3Client

http = SafeUrllib3Client()
response = http.request("GET", user_url)
content = response.data
```

Supported `PoolManager().request(...)` call sites can use an import alias:

```python
import safe_egress.urllib3_compat as urllib3

http = urllib3.PoolManager()
response = http.request("GET", user_url)
content = response.data
```

The facade also provides `urlopen`, context-manager use, and module-level
`request`. It rejects all `PoolManager` constructor options and unsupported
request options, including retries, proxies, streaming, and custom TLS. It is a
limited migration aid, not a full urllib3 replacement.

For standard-library `urllib.request` call sites, use the `urlopen`-style facade:

```python
from safe_egress.urllib_adapter import SafeUrllibOpener

with SafeUrllibOpener().open(user_url, timeout=5) as response:
    content = response.read()
```

These adapters do not patch process-wide functions. Requests, HTTPX, urllib3, and urllib request facades route through `SafeFetcher` and buffer bounded request/response bodies. `SafeRequestsSession` preserves the standard Requests cookie jar, supports trusted per-request `policy=` overrides, applies them across redirects, and locks its redirect cap, `mount()` method, environment-trust setting, and public adapter table after setup. It strips sensitive headers across origins and does not call Requests' redirect-auth hook, which can reapply `.netrc` credentials. `SafeClient` and `SafeAsyncClient` accept trusted per-request policies through `request()`, carry them across redirects, and require the override's redirect limit to match the client. `requests_compat` supports common module-level verbs, `Session` and `session()` construction, response/request types, and common exception aliases; it is still a limited facade, not a complete drop-in replacement. `SafeUrllib3Client`, `urllib3_compat`, and `SafeUrllibOpener` accept trusted per-request `policy=` overrides and apply them across redirect hops. The urllib3 facades support a small subset of `PoolManager.request` and module-level `request`; they reject unsupported constructor and request options, and do not implement pools, proxies, retries, streaming, or multipart encoding. `SafeUrllibOpener` handles only HTTP(S), bounded bodies, headers, and numeric timeouts; it does not implement opener handlers, cookies, proxies, custom TLS contexts, or streaming. The aiohttp adapter retains streaming and caps bytes returned by response read methods and iterators at `FetchPolicy.max_response_bytes`. aiohttp may buffer or decompress a chunk before the wrapper can enforce that limit, so the cap does not bound every transient internal allocation. The adapter checks redirects, caps redirect hops, strips sensitive headers on cross-origin hops, and disables proxies, session-wide auth, cookie jars, custom connectors, custom request and response classes, middleware, custom TLS settings, caller-supplied `Host` headers, URL credentials, and per-request cookies. Review each application's required features before using an adapter. The aiohttp adapter uses aiohttp's connector resolver, request-class, and response-class hooks; rerun its tests when upgrading aiohttp.

`SafeClient` and `SafeAsyncClient` are the HTTPX integrations for synchronous and asynchronous applications. Both disable environment proxy use and reject options that could replace the policy transport. Their transports are available for explicit wiring; installing one into a general HTTPX client with custom proxy mounts can route around it. `RequestsGet` remains a small GET-only facade for simple call sites.

## Current boundaries

- The transport uses direct HTTP(S) sockets and does not implement proxies, connection pooling, WebSockets, browser fetches, FTP, or arbitrary TCP protocols.
- Safe Egress has an experimental curl-cffi adapter with a pre-connect `OPENSOCKETFUNCTION` guard, but curl-cffi's native runtime and CVE fixture remain unverified in this environment; see the [CVE-2026-33752 notes](docs/client-cve-cases.md#experimental-adapter-curl-cffi-runtime-unverified). There is no adapter for Impit or Playwright networking. The Crawlee reproduction selects its optional HTTPX backend; it does not cover the default Impit backend. Crawlee v1 documents Impit as its default, and Impit's exposed Rust-backed `AsyncClient` API has no transport or resolver parameter, so the Safe HTTPX transport cannot be assumed to intercept it. curl-cffi's [maintainer PR #727](https://github.com/lexiforest/curl_cffi/pull/727) adds an opt-in safe redirect mode, while the default still follows redirects and the initial URL is not checked. Safe Egress's [adapter](src/safe_egress/curl_cffi_adapter.py) validates and pins each destination, checks the resolved peer before creating its socket, creates a fresh session per hop, and disables automatic redirects; verify it against the native client before relying on it. See [Crawlee's v1 migration notes](https://github.com/apify/crawlee-python/blob/v1.6.3/docs/upgrading/upgrading_to_v1.md), [Impit's Python API](https://apify.github.io/impit/python/), its [constructor signature](https://github.com/apify/impit/blob/master/impit-python/python/impit/impit.pyi#L3215-L3343), curl-cffi's [security notes](https://curl-cffi.readthedocs.io/en/latest/security.html), [session API](https://curl-cffi.readthedocs.io/en/latest/_modules/curl_cffi/requests/session.html), [low-level resolver option](https://curl-cffi.readthedocs.io/en/latest/_modules/curl_cffi/curl.html), [libcurl reset semantics](https://curl.se/libcurl/c/curl_easy_reset.html), and the [Crawlee case limits](examples/cve-repros/crawlee/README.md).
- Application code can bypass the policy by using another network client or opening sockets directly. Route untrusted fetches through a policy-bound client and apply network egress restrictions as a second boundary.
- The default port policy is intentionally limited to 80 and 443. Add other ports only when the feature needs them.
- DNS policy depends on the host OS resolver. All returned addresses are checked, then the selected numeric IP is used for the socket, avoiding a second hostname lookup for that connection.
- The classifier rejects IPv4-mapped IPv6, 6to4, Teredo, and the well-known NAT64 prefixes. It cannot identify every organization-specific translation or routing rule.
- Response bodies are buffered up to a configured decoded-byte limit. Unexpected gzip and deflate responses are decoded under that cap; unsupported content encodings fail closed. The timeout applies to individual socket operations; DNS resolution and redirects can make total request time longer. Attempts across multiple approved IPs share one connection timeout budget.
- See [the threat model and test plan](docs/threat-model.md) for the tested behaviors and remaining boundaries.

## CVE reproductions

Fixture-only cases are included for [Local Deep Research / Requests](examples/cve-repros/local-deep-research/README.md), [Kolibri / Requests](../kolibri-ssrf-benchmark/README.md), [Nanobot / HTTPX](examples/cve-repros/nanobot/README.md), [Crawlee / HTTPX](examples/cve-repros/crawlee/README.md), [LangChain / aiohttp](examples/langchain-ssrf/README.md), [PyJWT / urllib](examples/pyjwt-ssrf/README.md), [Glances / urllib](examples/glances-ssrf/README.md), [urllib3](examples/urllib3-cve-2025-50181/README.md), and [curl-cffi](examples/cve-repros/curl-cffi/README.md). The curl-cffi socket fixture is ready to run with the pinned versions but remains unverified in this sandbox. The other cases compare vulnerable call paths, maintainer-fixed behavior where available, and Safe Egress integrations. Fixture exchanges use dummy responses and synthetic routing and do not contact external services.


## Install from a checkout

```sh
python -m pip install .
```

Python 3.11 or newer is required. There are no runtime dependencies.
