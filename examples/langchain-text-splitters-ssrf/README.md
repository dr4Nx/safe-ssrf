# LangChain Text Splitters Requests SSRF case

This fixture-only case evaluates [CVE-2026-41481](https://github.com/advisories/GHSA-fv5p-p927-qmxr), a redirect bypass in `HTMLHeaderTextSplitter.split_text_from_url()`. The vulnerable method validates its initial URL and then calls `requests.get()` with redirects enabled. Version 1.1.2 deprecates the method and fetches through LangChain Core's SSRF-safe HTTPX client.

## Revisions

- Repository: [langchain-ai/langchain](https://github.com/langchain-ai/langchain)
- Vulnerable tag: `langchain-text-splitters==1.1.1`, commit `269947b11f3b78eb800dd3fe12f3c07151ac9feb`
- Fixed tag: `langchain-text-splitters==1.1.2`, commit `58c4e5bbdd9d18d7fe7ec83b5a05477d06fe2a8e`
- The tags are already present in the local `ssrf-study-source-full` clone. To prepare fresh source worktrees:

```sh
git clone https://github.com/langchain-ai/langchain.git ../langchain-source
git -C ../langchain-source worktree add --detach ../langchain-text-splitters-vuln 'langchain-text-splitters==1.1.1'
git -C ../langchain-source worktree add --detach ../langchain-text-splitters-fixed-1.1.2 'langchain-text-splitters==1.1.2'
```

## Local reproduction and integration

The test extracts and executes the actual `split_text_from_url()` method body from each tagged source tree. The vulnerable run uses Requests' real redirect machinery with an in-memory `BaseAdapter`: a public fixture redirects to a simulated loopback service containing dummy text. Synthetic DNS makes the vulnerable validator accept only the public first hop. No sockets or external requests are made.

The fixed-source test executes the 1.1.2 method and LangChain Core's actual `ssrf_safe_client()` factory. Its HTTPX transport's final in-memory transport is stubbed, while URL validation and redirect handling remain active. A companion integration substitutes Safe Egress' [SafeClient](../../src/safe_egress/adapters/httpx/__init__.py) factory at that same call site; it blocks the redirect and still returns public fixture text to the splitter. The focused redirect tests use a small parser stand-in. When BeautifulSoup is installed, an additional test imports the tagged production splitter and verifies real HTML parsing, document splitting, and header metadata.

Run the fixture tests and full local evaluator from the Safe Egress repository root:

```sh
PYTHONPATH=src python3.11 -m unittest discover \
  -s examples/langchain-text-splitters-ssrf -p 'test_*.py' -v

PYTHONPATH=src /path/to/python-with-pytest examples/langchain-text-splitters-ssrf/run_eval.py \
  --vulnerable-repo ../langchain-text-splitters-vuln \
  --fixed-repo ../langchain-text-splitters-fixed-1.1.2 \
  --output-dir examples/langchain-text-splitters-ssrf/results/recheck
```

The evaluator records both package build attempts, both focused upstream test attempts, fixture results, source commits, commands, and elapsed time. It sets `PIP_NO_INDEX=1` and never installs dependencies.

## Current environment results and limits

The redirect fixture tests pass under the existing Python 3.11.17 Poetry environment, Requests 2.32.3, and HTTPX 0.27.0; the production-parser test skips because BeautifulSoup is absent there. All four tests pass under Python 3.13. The production-parser test verifies that a public HTML page still yields separate title/body documents with the expected title metadata. Both runs use local in-memory transports and synthetic DNS; no network connections are made. The latest Python 3.11 evaluator report is [`results/recheck-20261020/evaluation.json`](results/recheck-20261020/evaluation.json).

Both package wheel builds stop because `hatchling.build` is not installed. Both upstream test collections stop because `uuid_utils` is missing. No dependencies were installed. These are environment blockers, not test failures in the vulnerable or fixed package code; package builds and the full upstream suite remain unverified here.

The current fixture verifies fetch/redirect policy and passes the returned HTML into a small parser stand-in. It does not exercise BeautifulSoup's production document-splitting implementation. The compatibility test uses the fixed source's synchronous `ssrf_safe_client()` interface; it does not cover unrelated LangChain Text Splitter APIs or application-specific policy customization.
