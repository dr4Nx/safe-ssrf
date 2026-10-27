# Threat model and test plan

## Goal

Prevent common server-side request forgery paths when an application fetches a user-influenced HTTP(S) URL through `SafeFetcher`.

## Protected behaviors

The current implementation is intended to:

- Accept only HTTP and HTTPS URLs with unambiguous host syntax.
- Reject non-canonical numeric IPv4 URL hosts (shortened, octal, hexadecimal, or integer spellings) before DNS resolution, so URL parsers and the pinned transport cannot interpret the same host differently.
- Reject URL credentials, fragments, controls, whitespace, backslashes, and encoded authority syntax.
- Enforce exact optional host and port allowlists.
- Resolve hostnames, reject resolution failure and empty answers, and reject the whole host if any answer is prohibited.
- Pin each socket connection to a checked numeric IP while preserving the original hostname for the HTTP Host header and TLS verification. If connection setup fails, try another already-checked answer within one shared connection timeout budget; do not retry after writing the HTTP request.
- Re-apply URL, host, port, and address checks to every redirect.
- Allow a trusted Requests call site to supply a request-scoped `FetchPolicy`; apply it to every redirect and restore the prior context after completion or error.
- Strip authorization, cookie, origin, referer, and common API-key headers after a cross-origin redirect; allow callers to configure application-specific secret header names.
- Keep Requests environment trust disabled after session setup and do not delegate redirect-auth rebuilding, which can reapply `.netrc` credentials after a header was stripped.
- Avoid implicit proxies and bound per-operation time, redirect count, request body size, and response body size.
- Decode unexpected gzip/deflate response bodies with an output limit equal to `max_response_bytes`; reject unsupported or malformed content encodings.

The aiohttp adapter enforces these destination checks using a custom TCP connector resolver. aiohttp bypasses that resolver for IP literals, so the adapter also validates parsed request URLs through its documented request-class hook before the connector runs. It rejects non-HTTP(S) schemes, disallowed ports, prohibited IP literals, URL credentials, fragments, caller-supplied `Host` headers, per-request cookies, session-wide authentication, proxies, custom cookie jars, custom connectors, and custom request classes. DNS results for hostnames are all checked before aiohttp receives numeric addresses. An internal redirect trace removes the configured sensitive-header set on cross-origin redirects; the trace is appended after caller traces so they cannot re-add those headers afterward. Session-wide auth is refused because aiohttp can reapply its default auth after the redirect code clears it.

The aiohttp adapter wraps the response reader and enforces `FetchPolicy.max_response_bytes` for buffered methods (`read`, `text`, and `json`) and streaming methods on the public reader. It closes the response when the limit is exceeded. The response remains streamed; the adapter does not buffer the entire body to enforce the cap. aiohttp may buffer or decompress an incoming chunk before the wrapper sees it, so this caps bytes returned to the caller but does not bound every transient parser/decompressor allocation.

The aiohttp adapter rejects known-size request bodies above `FetchPolicy.max_request_bytes` before opening a connection. Unknown-size streaming bodies are capped at aiohttp's request writer boundary; a chunk that would exceed the limit is not forwarded. aiohttp reports this streamed-body rejection as a client connection error with the policy exception as its cause. The request headers and any earlier, under-limit body chunks may already have been sent when the limit is crossed.

`allowed_ips` provides exact address exceptions for private or special-use peers. Every DNS answer is still checked independently: public unicast answers pass, listed non-multicast addresses pass, and any other non-public answer rejects the whole hostname. An IP exception is not bound to a DNS name: if `allowed_hosts` is unset, any hostname resolving to a listed address can use it, while the HTTP Host authority remains that URL's hostname. Pair the IP with an exact `allowed_hosts` entry when the request must reach one named service or virtual host. This avoids trusting a hostname's entire private DNS answer set and prevents a rebind to an unlisted address.

Multicast is always rejected, including when its address appears in `allowed_ips`. Python's `ipaddress.is_global` returns true for multicast ranges, so the policy explicitly excludes them before applying its public-address rule. Tests cover IPv4 and IPv6 multicast and confirm rejection occurs before DNS or transport use.

The standard-library classification can lag the IANA registries. The policy supplements it by denying `192.88.99.0/24`, `100:0:0:1::/64`, and `5f00::/16`, which IANA identifies as deprecated or not globally reachable, and by accepting the globally reachable `2001:1::3/128` anycast assignment even on Python releases that classify the broader prefix as private. The relevant entries are in the [IANA IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry), the [IANA IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry), and the [IPv4 address-space registry](https://www.iana.org/assignments/ipv4-address-space). Review these explicit ranges when updating Python or the registries.

There is no hostname-based exception for non-public addresses. A private service must be listed by exact IP, and an optional exact hostname allowlist restricts which URL may use that address. If the service changes IP, update the policy; a stale address fails closed.

The default policy permits every globally routable destination, so it does not stop a caller-controlled URL from sending data or attached credentials to an attacker-owned public server. When the destination must be a particular service—especially for requests carrying credentials—set an exact `allowed_hosts` list from trusted application configuration, independent of the URL input. The Glances `public_api` case demonstrates this distinction: private-address filtering blocks loopback, while the application also needs a host allowlist to keep configured Basic credentials away from an arbitrary public host.

Cross-origin redirects remove a standard set of credential headers, including common API-key headers, session tokens, AWS IMDSv2 tokens, and Vault/Consul tokens. They also remove `Referer`, which can carry sensitive query strings across origins. Applications that use a custom secret header must list it in `FetchPolicy.additional_sensitive_headers`; otherwise it may be forwarded to another public origin after a redirect. Headers are retained on same-origin redirects.

## Validated destination API

`SafeFetcher.validate_destination(url, policy=...)` parses a URL, checks its scheme, exact host and port policy, resolves the hostname, rejects the destination if any answer is disallowed, and returns a `ValidatedDestination` with the normalized host, port, request target, and every approved numeric address. It does not connect, follow redirects, enforce response limits, or make an arbitrary client safe by itself. An adapter must pin the actual transport to one returned address and repeat validation for each redirect; sending the original hostname through a client that resolves it again reopens the DNS-rebinding race. Do not trust a caller-constructed `ValidatedDestination`; use the result returned by `validate_destination` for that request hop.

## Out of scope

- Calls that bypass `SafeFetcher`.
- Requests features outside the `SafeRequestsSession` adapter's documented request contract.
- Browser engines, WebSockets, proxy-mediated egress, non-HTTP protocols, and clients that do not use this package.
- Organization-specific routing, NAT, service meshes, or policy outside the process.
- A guarantee that every globally routable address is safe for every application.
- Per-origin isolation for the standard Requests cookie jar on independently initiated requests. Cross-origin redirects strip `Cookie`, but cookie matching otherwise follows Requests' normal domain and path rules, so a separate request to a sibling host can send a cookie whose `Domain` attribute covers it. Do not share a cookie-bearing session with arbitrary user-selected hosts when broad-domain cookies are present; use a dedicated session or an exact host allowlist.
- Limits on content further decoded by downstream code and on transient internal allocations made by aiohttp's parser or decompressor before the response wrapper observes a chunk.

## Automated local validation

Run `PYTHONPATH=src python -m unittest discover -v`. Install the optional client extras to run their adapter tests (`python -m pip install '.[requests,httpx,aiohttp]'`). Most tests use controlled resolver records and in-memory simulated services. One optional integration test binds an ephemeral loopback listener when the environment permits it; no test contacts public hosts or real internal services.

1. Direct loopback, private IPv4/IPv6, link-local, metadata, shared-address, reserved, mapped, and transition addresses are rejected before the fixture receives a connection.
2. Exact IP exceptions permit a configured private fixture address while rejecting an unlisted rebound address and mixed DNS answers, including when the hostname itself is allowlisted.
3. A public-policy request succeeds against a simulated public resolver result and confirms the transport receives the validated numeric address while the HTTPS connection retains the original hostname.
4. Mixed public/private DNS answers fail closed; resolver exceptions and empty results fail closed.
5. A public fixture redirecting to a prohibited local fixture is rejected before the second fixture receives a connection. Absolute and scheme-relative loopback redirects are checked through Requests, HTTPX, and aiohttp; same-origin relative redirects, redirect loops, and the hop limit are also covered.
6. Parser cases include userinfo, malformed IPv6 brackets, numeric IPv4 variants, Unicode full stops that client parsers normalize to loopback, backslashes, controls, whitespace, invalid ports, encoded authority, and fragments.
7. Cross-origin redirects remove standard credentials, common API-key headers, and configured application-specific secret headers; same-origin redirects preserve intended headers. Requests, aiohttp, sync/async HTTPX, urllib3, urllib, and SafeFetcher tests exercise the policy. Requests and sync/async HTTPX tests verify that client-level BasicAuth and domain cookies reach the first origin and are removed before a cross-origin hop.
8. Public utility behavior returns the simulated body, status, headers, final URL, and redirect history. Oversized wire and decoded bodies are rejected; gzip and deflate utility responses are decoded within the same cap.
9. A socket-mocked test verifies the final `socket.connect()` argument is the checked numeric IPv4 or IPv6 address and makes no resolver call. A separate optional loopback integration test starts a real IPv4 HTTP listener, supplies a synthetic DNS answer, and verifies that the client connects to the checked numeric address while preserving the hostname in the `Host` header. It skips when the environment forbids binding. Real IPv6 and TLS socket behavior still need controlled runs on target platforms.
10. aiohttp adapter tests cover numeric-address resolver output, mixed public/private answers, loopback literal rejection before the connector, exact IP exceptions, hostname rebinding rejection, caller-supplied `Host` rejection, URL credential and cookie rejection, known-size request rejection before connector use, streamed request rejection before an over-limit chunk reaches the transport, public response parsing at the exact size limit, buffered and streamed oversized-response rejection, public-to-loopback redirect rejection before a second connection, cross-origin header and per-request BasicAuth stripping, rejection of session-wide auth, proxy rejection, and constructor options that could replace routing.
11. Requests adapter tests cover a per-call policy exception for one exact private IP, policy rechecking on a redirected public host, successful public fetches under a per-call host allowlist, no policy leakage between sequential or concurrent calls, redirect-hop limits, 307 POST-body preservation, persistence of multiple `Set-Cookie` headers on same-origin requests, withholding a response-supplied domain cookie on a cross-origin redirect, session BasicAuth and cookie-jar stripping on cross-origin redirects, rejection of attempts to re-enable environment trust, no `.netrc` auth reapplication on HTTPS-to-HTTP redirects, and multipart rejection before Requests reads the upload file.
12. The Requests compatibility facade tests cover module-level public `get`, both `Session` and `session()` safe constructors, Requests request/response type aliases, top-level exception aliases, caller-supplied exact private policy, and rejection of the default loopback target and proxy routing.
13. Sync and async HTTPX tests cover client-level BasicAuth and cookie-jar stripping on cross-origin redirects, public response handling, redirect rejection before an internal transport send, request-body limits, and rejection of options that could replace the policy-bound transport.
14. Socket-mocked connection tests confirm a pre-request failure can fall through to another already-validated IP within one shared connection timeout budget, record the successful peer, restore the normal socket timeout after connection, and avoid retrying when the request write fails.
15. `validate_destination` tests confirm normalized host/port and request-target output, expose all approved public DNS answers without connecting, honor an exact per-call private-IP exception, and reject mixed public/private answers.

The transition-address regression includes `64:ff9b:1::7f00:1`, an address inside the policy's network-specific NAT64 prefix. Policy and core fetcher tests pass on Python 3.11, 3.13, and 3.14; the fetcher test confirms rejection before `_send`. The [saved run report](../results/nat64-policy-regression-20261020/evaluation.json) records each command and result. Current system Python 3.11 unittest discovery ran 184 tests with 98 skips because optional client dependencies are unavailable.

The current suite covers the deterministic in-process checks above. The real loopback socket test was skipped here because binding a local listener is denied with `PermissionError`; the new IPv4/IPv6 socket-mocked check validates the requested connect address but does not exercise a kernel socket. TLS handshakes, OS resolver behavior, network namespaces, real IPv6 sockets, and every supported Python version are not yet validated. Passing the suite is not proof of complete SSRF protection.
