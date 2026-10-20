# safe-egress

A small Python prototype for fetching attacker-influenced HTTP(S) URLs while enforcing destination policy at the socket connection. The core runtime has no third-party dependencies; the Requests, HTTPX, and aiohttp adapters are optional.

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

The default policy allows globally routable destinations on ports 80 and 443. It rejects private, loopback, link-local, reserved, and special-use destinations. Every DNS answer must pass the policy; the fetcher then dials one checked numeric address. HTTPS still uses the original hostname for SNI and certificate verification. Redirects are followed manually and revalidated one hop at a time.

For an integration that intentionally uses a private service, configure an exact hostname allowlist and a separate exact private-host exception:

```python
policy = FetchPolicy(
    allowed_hosts=frozenset({"files.example.net", "internal-files.corp.example"}),
    allowed_private_hosts=frozenset({"internal-files.corp.example"}),
)
```

Avoid broad suffix matching. The exception trusts that exact name and its resolved addresses, so it should only be used for a service your application controls.

`allowed_private_hosts` is a full trust exception for each exact configured hostname: it bypasses the public-address classification for every address returned for that name, including loopback, link-local, and reserved ranges. Use it only when the application controls the hostname and its DNS. It does not support suffix or wildcard matching.

## Development checks

Run the dependency-free core suite:

```sh
PYTHONPATH=src python3.11 -m unittest discover -v
```

The tests never bind a port or contact an external system. Controlled resolver records and in-memory transports exercise request decisions and response handling. Adapter tests are skipped when their optional clients are absent. To run the complete adapter suite, provision the optional dependencies first, then run the same command:

```sh
python3.11 -m pip install -e '.[requests,httpx,aiohttp,urllib3]'
PYTHONPATH=src python3.11 -m unittest discover -v
```

The optional install requires package access; no package download is needed for the core suite. Actual OS resolver and socket behavior still need a separately controlled integration environment.

The optional `safe-egress-audit` command inventories some common direct network calls in Python source (after installing the package; from a checkout, use `PYTHONPATH=src python -m safe_egress.audit`):

```sh
safe-egress-audit path/to/source
```

It is a heuristic sink inventory, not taint analysis or proof that SSRF is absent. It may miss wrapper methods, dynamic imports, custom clients, browser traffic, raw socket usage, and indirect session calls.

## Client adapters

Install only the client extras you need:

```sh
python -m pip install 'safe-egress[requests,httpx,aiohttp,urllib3]'
```

For Requests code that needs a Session:

```python
from safe_egress import FetchPolicy
from safe_egress.requests_adapter import SafeRequestsSession

with SafeRequestsSession(policy=FetchPolicy()) as session:
    response = session.get(user_url, headers={"Accept": "text/html"}, timeout=8)
```

For common module-level calls, replace the Requests import with the scoped compatibility facade:

```python
import safe_egress.requests_compat as requests

response = requests.get(user_url, timeout=8)
with requests.Session() as session:
    response = session.post(upload_url, data=b"bounded body")
```

The facade provides `request`, `get`, `options`, `head`, `post`, `put`, `patch`, `delete`, and `Session`, along with Requests response and exception types. It is not a full Requests implementation: unsupported options such as proxies, streaming, custom TLS configuration, and multipart uploads fail closed in the adapter.

An application can supply a trusted, request-specific policy when one fetch needs a different destination set:

```python
from safe_egress import FetchPolicy
from safe_egress.requests_adapter import SafeRequestsSession

internal_files = FetchPolicy(
    allowed_hosts=frozenset({"files.internal.example"}),
    allowed_private_hosts=frozenset({"files.internal.example"}),
)
with SafeRequestsSession() as session:
    response = session.get(file_url, policy=internal_files)
```

The request policy replaces the session policy for that call, including on redirects. Treat policy objects as trusted application configuration; never build one directly from request input. Its `max_redirects` must match the session's configured limit. A private-host exception trusts every address resolved for that exact hostname.

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

For aiohttp code, create a session with the policy resolver:

```python
from safe_egress import FetchPolicy
from safe_egress.aiohttp_adapter import safe_aiohttp_session

async with safe_aiohttp_session(policy=FetchPolicy()) as session:
    async with session.get(user_url) as response:
        content = await response.read()
```

For code that directly uses urllib3, use the narrow request facade:

```python
from safe_egress.urllib3_adapter import SafeUrllib3Client

http = SafeUrllib3Client()
response = http.request("GET", user_url)
content = response.data
```

For standard-library `urllib.request` call sites, use the `urlopen`-style facade:

```python
from safe_egress.urllib_adapter import SafeUrllibOpener

with SafeUrllibOpener().open(user_url, timeout=5) as response:
    content = response.read()
```

These adapters do not patch process-wide functions. Requests, HTTPX, urllib3, and urllib request facades route through `SafeFetcher` and buffer bounded request/response bodies. `SafeRequestsSession` supports trusted per-request `policy=` overrides, applies them across redirects, and locks its redirect cap, `mount()` method, and public adapter table after setup. `requests_compat` offers a limited module-shaped facade for common Requests calls and `Session`; it is not a complete drop-in replacement. `SafeUrllib3Client` is not a `PoolManager` subclass: it supports a deliberately small request interface, rejects unknown options, and does not implement pools, proxies, retries, streaming, or multipart encoding. `SafeUrllibOpener` handles only HTTP(S), bounded bodies, headers, and numeric timeouts; it does not implement opener handlers, cookies, proxies, custom TLS contexts, or streaming. The aiohttp adapter retains streaming and caps bytes returned by response read methods and iterators at `FetchPolicy.max_response_bytes`. aiohttp may buffer or decompress a chunk before the wrapper can enforce that limit, so the cap does not bound every transient internal allocation. The adapter checks redirects, caps redirect hops, strips sensitive headers on cross-origin hops, and disables proxies, cookie jars, custom connectors, custom request and response classes, middleware, custom TLS settings, caller-supplied `Host` headers, URL credentials, and per-request cookies. Review each application's required features before using an adapter. The aiohttp adapter uses aiohttp's connector resolver, request-class, and response-class hooks; rerun its tests when upgrading aiohttp.

`SafeClient` and `SafeAsyncClient` are the HTTPX integrations for synchronous and asynchronous applications. Both disable environment proxy use and reject options that could replace the policy transport. Their transports are available for explicit wiring; installing one into a general HTTPX client with custom proxy mounts can route around it. `RequestsGet` remains a small GET-only facade for simple call sites.

## Current boundaries

- The transport uses direct HTTP(S) sockets and does not implement proxies, connection pooling, WebSockets, browser fetches, FTP, or arbitrary TCP protocols.
- Application code can bypass the policy by using another network client or opening sockets directly. Route untrusted fetches through a policy-bound client and apply network egress restrictions as a second boundary.
- The default port policy is intentionally limited to 80 and 443. Add other ports only when the feature needs them.
- DNS policy depends on the host OS resolver. All returned addresses are checked, then the selected numeric IP is used for the socket, avoiding a second hostname lookup for that connection.
- The classifier rejects IPv4-mapped IPv6, 6to4, Teredo, and the well-known NAT64 prefixes. It cannot identify every organization-specific translation or routing rule.
- Response bodies are buffered up to a configured limit. The timeout applies to socket operations, not a strict end-to-end deadline.
- See [the threat model and test plan](docs/threat-model.md) for the tested behaviors and remaining boundaries.

## CVE reproductions

Runnable, fixture-only cases are included for [Local Deep Research / Requests](examples/cve-repros/local-deep-research/README.md), [Nanobot / HTTPX](examples/cve-repros/nanobot/README.md), [LangChain / aiohttp](examples/langchain-ssrf/README.md), [PyJWT / urllib](examples/pyjwt-ssrf/README.md), and [urllib3](examples/urllib3-cve-2025-50181/README.md). The cases requiring external application repositories use separate source worktrees at documented public revisions; their graders and commands live in this repository. All reproductions use dummy responses and synthetic routing. They do not contact external services.

## Install from a checkout

```sh
python -m pip install .
```

Python 3.11 or newer is required. There are no runtime dependencies.
