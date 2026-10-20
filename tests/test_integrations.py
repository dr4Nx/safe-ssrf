import importlib.util
import unittest
from unittest.mock import Mock

from safe_egress import FetchResponse, RequestsGet


@unittest.skipUnless(importlib.util.find_spec("requests"), "optional requests dependency is not installed")
class RequestsGetTests(unittest.TestCase):
    def test_requests_response_is_backed_by_safe_fetcher(self) -> None:
        fetcher = Mock()
        fetcher.get.return_value = FetchResponse(
            status_code=200,
            headers=(("Content-Type", "text/plain; charset=utf-8"), ("X-Fixture", "yes")),
            content=b"dummy utility response",
            url="https://public.example/final",
            history=("https://public.example/start",),
        )
        client = RequestsGet(fetcher)
        response = client.get("https://public.example/start", headers={"Accept": "text/plain"})

        fetcher.get.assert_called_once_with("https://public.example/start", headers={"Accept": "text/plain"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "dummy utility response")
        self.assertEqual(response.headers["x-fixture"], "yes")
        self.assertEqual(response.url, "https://public.example/final")
        # This adapter intentionally does not fabricate Requests redirect objects.
        self.assertEqual(response.history, [])

    def test_does_not_accept_unimplemented_requests_options(self) -> None:
        client = RequestsGet(Mock())
        with self.assertRaises(TypeError):
            client.get("https://public.example", timeout=1)


if __name__ == "__main__":
    unittest.main()
