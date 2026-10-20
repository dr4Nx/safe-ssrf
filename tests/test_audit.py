import unittest

from safe_egress.audit import scan_source


class SinkInventoryTests(unittest.TestCase):
    def test_finds_direct_calls_through_module_aliases_and_import_aliases(self) -> None:
        source = """
import requests as rq
from urllib.request import urlopen as open_url
import aiohttp
from requests import Session

rq.get(user_url)
open_url(user_url)
aiohttp.ClientSession().get(user_url)
session = Session()
session.post(user_url)
"""
        findings = scan_source(source, "sample.py")
        self.assertEqual([finding.line for finding in findings], [7, 8, 9, 11])
        self.assertEqual([finding.call for finding in findings], [
            "requests.get", "urllib.request.urlopen", "aiohttp.ClientSession.get", "requests.Session.post"
        ])

    def test_ignores_unrelated_methods_and_documents_heuristic_limits(self) -> None:
        source = """
class Store:
    def get(self, key):
        return key

Store().get("value")
"""
        self.assertEqual(scan_source(source), [])

    def test_finds_direct_urllib3_pool_calls_and_aliases(self) -> None:
        source = """
import urllib3 as u3
from urllib3 import PoolManager as Manager
pool = u3.PoolManager()
other = Manager()
pool.request('GET', user_url)
other.urlopen('GET', user_url)
urllib3.request('GET', user_url)
"""
        calls = [finding.call for finding in scan_source(source)]
        self.assertIn("urllib3.PoolManager.request", calls)
        self.assertIn("urllib3.PoolManager.urlopen", calls)
        self.assertIn("urllib3.request", calls)

    def test_distinguishes_policy_bound_clients_from_raw_sessions(self) -> None:
        source = """
import requests
import safe_egress.requests_adapter as safe_requests
from safe_egress.httpx_adapter import SafeAsyncClient as SafeHTTPX

with safe_requests.SafeRequestsSession() as safe_session:
    safe_session.get(user_url)

async def fetch():
    async with SafeHTTPX() as safe_client:
        await safe_client.get(user_url)

raw_session = requests.Session()
raw_session.get(user_url)
"""
        findings = scan_source(source, "sample.py")
        self.assertEqual([finding.call.rsplit(".", 1)[-1] for finding in findings], ["get", "get", "get"])
        self.assertEqual([finding.policy_bound for finding in findings], [True, True, False])

    def test_recognizes_all_safe_client_wrappers(self) -> None:
        source = """
from safe_egress import SafeFetcher
from safe_egress.aiohttp_adapter import safe_aiohttp_session
from safe_egress.urllib3_adapter import SafeUrllib3Client
from safe_egress.urllib_adapter import SafeUrllibOpener

fetcher = SafeFetcher()
fetcher.get(user_url)
with safe_aiohttp_session() as session:
    session.get(user_url)
http = SafeUrllib3Client()
http.request('GET', user_url)
opener = SafeUrllibOpener()
opener.open(user_url)
"""
        findings = scan_source(source, "safe_clients.py")
        self.assertEqual(len(findings), 4)
        self.assertTrue(all(finding.policy_bound for finding in findings))


if __name__ == "__main__":
    unittest.main()
