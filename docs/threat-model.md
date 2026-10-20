# Threat model and test plan

## Goal

Prevent common server-side request forgery paths when an application fetches a user-influenced HTTP(S) URL through `SafeFetcher`.

## Protected behaviors

The current implementation is intended to:

- Accept only HTTP and HTTPS URLs with unambiguous host syntax.
- Reject URL credentials, fragments, controls, whitespace, backslashes, and encoded authority syntax.
- Enforce exact optional host and port allowlists.
- Resolve hostnames, reject resolution failure and empty answers, and reject the whole host if any answer is prohibited.
- Pin each socket connection to a checked numeric IP while preserving the original hostname for the HTTP Host header and TLS verification.
- Re-apply URL, host, port, and address checks to every redirect.
- Allow a trusted Requests call site to supply a request-scoped `FetchPolicy`; apply it to every redirect and restore the prior context after completion or error.
- Strip authorization, cookie, and origin headers after a cross-origin redirect.
- Avoid implicit proxies and bound per-operation time, redirect count, and buffered response size.
- Decode unexpected gzip/deflate response bodies with an output limit equal to `max_response_bytes`; reject unsupported or malformed content encodings.

The aiohttp adapter enforces these destination checks using a custom TCP connector resolver. aiohttp bypasses that resolver for IP literals, so the adapter also validates parsed request URLs through its documented request-class hook before the connector runs. It rejects non-HTTP(S) schemes, disallowed ports, prohibited IP literals, URL credentials, fragments, caller-supplied `Host` headers, per-request cookies, session-wide authentication, proxies, custom cookie jars, custom connectors, and custom request classes. DNS results for hostnames are all checked before aiohttp receives numeric addresses. An internal redirect trace removes authorization, cookie, and origin headers on cross-origin redirects; the trace is appended after caller traces so they cannot re-add those headers afterward. Session-wide auth is refused because aiohttp can reapply its default auth after the redirect code clears it.

The aiohttp adapter wraps the response reader and enforces `FetchPolicy.max_response_bytes` for buffered methods (`read`, `text`, and `json`) and streaming methods on the public reader. It closes the response when the limit is exceeded. The response remains streamed; the adapter does not buffer the entire body to enforce the cap. aiohttp may buffer or decompress an incoming chunk before the wrapper sees it, so this caps bytes returned to the caller but does not bound every transient parser/decompressor allocation.

The current `allowed_private_hosts` setting is a deliberate full-trust exception for an exact normalized hostname. It permits every address returned for that name, even if an answer is loopback, link-local, metadata, or reserved. This makes DNS and hostname ownership part of the caller's trust boundary. Do not configure attacker-controlled or remotely delegated hostnames.

## Out of scope

- Calls that bypass `SafeFetcher`.
- Requests features outside the `SafeRequestsSession` adapter's documented request contract.
- Browser engines, WebSockets, proxy-mediated egress, non-HTTP protocols, and clients that do not use this package.
- Organization-specific routing, NAT, service meshes, or policy outside the process.
- A guarantee that every globally routable address is safe for every application.
- Limits on content further decoded by downstream code and on transient internal allocations made by aiohttp's parser or decompressor before the response wrapper observes a chunk.

## Automated local validation

Run `PYTHONPATH=src python -m unittest discover -v`. Install the optional client extras to run their adapter tests (`python -m pip install '.[requests,httpx,aiohttp]'`). Most tests use controlled resolver records and in-memory simulated services. One optional integration test binds an ephemeral loopback listener when the environment permits it; no test contacts public hosts or real internal services.

1. Direct loopback, private IPv4/IPv6, link-local, metadata, shared-address, reserved, mapped, and transition addresses are rejected before the fixture receives a connection.
2. A test-only exact private-host exception reaches only its configured local fixture.
3. A public-policy request succeeds against a simulated public resolver result and confirms the transport receives the validated numeric address while the HTTPS connection retains the original hostname.
4. Mixed public/private DNS answers fail closed; resolver exceptions and empty results fail closed.
5. A public fixture redirecting to a prohibited local fixture is rejected before the second fixture receives a connection. Relative redirects, redirect loops, and the hop limit are covered.
6. Parser cases include userinfo, malformed IPv6 brackets, numeric IPv4 variants, backslashes, controls, whitespace, invalid ports, encoded authority, and fragments.
7. Cross-origin redirects remove authorization, cookie, and origin headers; same-origin redirects preserve intended headers.
8. Public utility behavior returns the simulated body, status, headers, final URL, and redirect history. Oversized wire and decoded bodies are rejected; gzip and deflate utility responses are decoded within the same cap.
9. An optional loopback integration test starts a real IPv4 HTTP listener, supplies a synthetic DNS answer, and verifies that the client connects to the checked numeric address while preserving the hostname in the `Host` header. It skips when the environment forbids binding. IPv6 and TLS socket behavior still need controlled runs on target platforms.
10. aiohttp adapter tests cover numeric-address resolver output, mixed public/private answers, loopback literal rejection before the connector, exact private-host exceptions, caller-supplied `Host` rejection, URL credential and cookie rejection, public response parsing at the exact size limit, buffered and streamed oversized-response rejection, public-to-loopback redirect rejection before a second connection, cross-origin header and per-request BasicAuth stripping, rejection of session-wide auth, proxy rejection, and constructor options that could replace routing.
11. Requests adapter tests cover a per-call policy exception for one exact private host, policy rechecking on a redirected public host, successful public fetches under a per-call host allowlist, no policy leakage between sequential or concurrent calls, redirect-hop limits, 307 POST-body preservation, and multipart rejection before Requests reads the upload file.
12. The Requests compatibility facade tests cover module-level public `get`, `Session` aliasing to the safe session, caller-supplied exact private policy, and rejection of the default loopback target and proxy routing.

The current suite covers the deterministic in-process checks above. The real loopback socket test was skipped here because binding a local listener is denied with `PermissionError`; TLS handshakes, OS resolver behavior, network namespaces, IPv6 sockets, and every supported Python version are not yet validated. Passing the suite is not proof of complete SSRF protection.
