from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import unittest
from unittest.mock import patch

from safe_egress import FetchPolicy, SafeFetcher


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.server.observed_host = self.headers.get("Host")  # type: ignore[attr-defined]
        self.server.observed_path = self.path  # type: ignore[attr-defined]
        body = b"LOCAL_SOCKET_FIXTURE_OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return None


class SocketIntegrationTests(unittest.TestCase):
    def test_checked_address_is_used_for_real_loopback_socket(self) -> None:
        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        except PermissionError as exc:
            self.skipTest(f"this environment does not permit loopback binds: {exc}")

        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_port
        lookups: list[tuple[str, int]] = []

        def synthetic_resolver(host: str, requested_port: int, *args: object, **kwargs: object):
            del args, kwargs
            lookups.append((host, requested_port))
            if host != "fixture.public.test" or requested_port != port:
                raise AssertionError(f"unexpected resolver call: {host}:{requested_port}")
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("127.0.0.1", port),
                )
            ]

        try:
            policy = FetchPolicy(
                allowed_hosts=frozenset({"fixture.public.test"}),
                allowed_ips=frozenset({"127.0.0.1"}),
                allowed_ports=frozenset({port}),
            )
            fetcher = SafeFetcher(policy)
            with patch("safe_egress.client.socket.getaddrinfo", side_effect=synthetic_resolver):
                response = fetcher.get(f"http://fixture.public.test:{port}/socket-check")

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b"LOCAL_SOCKET_FIXTURE_OK")
            self.assertEqual(lookups, [("fixture.public.test", port)])
            self.assertEqual(server.observed_host, f"fixture.public.test:{port}")
            self.assertEqual(server.observed_path, "/socket-check")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
