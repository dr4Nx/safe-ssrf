# LangChain WebResearchRetriever / aiohttp case

This fixture-only integration exercises the LangChain Community path associated with [CVE-2024-3095](https://github.com/advisories/GHSA-q25c-c977-4cmh). The vulnerable `AsyncHtmlLoader` passes search-result URLs to aiohttp; the hardened companion loader uses `safe_aiohttp_session` for async fetches and `SafeRequestsSession` for its separate synchronous helper.

## Revisions

- Repository: [langchain-ai/langchain](https://github.com/langchain-ai/langchain)
- Vulnerable tag and commit: `langchain-community==0.2.7`, `007c5a85d5264203ec0e0a6c44eb13b079bfb984`
- Fixed tag and commit: `langchain-community==0.2.9`, `f4ee3c8a223ea4b3d7bd9e08fcd3769c70e3446c`
- The maintainer release requires explicit `allow_dangerous_requests=True`; this experiment instead checks that the transport policy blocks private destinations.

## Prepare the source worktrees

From the Safe Egress repository root:

```sh
mkdir -p ../ssrf-study
git clone https://github.com/langchain-ai/langchain.git ../langchain-source
git -C ../langchain-source worktree add --detach ../ssrf-study/checkout langchain-community==0.2.7
git -C ../langchain-source worktree add --detach ../langchain-community-fixed-0.2.9 langchain-community==0.2.9
```

The prepared workspace used those paths. Install or provision LangChain's Poetry dependencies before running the commands below. Package installation may require access to the configured package index; the test cases themselves make no network requests.

## Check the release behavior

Run from the Safe Egress repository root. The script constructs a retriever with dummy components and performs no fetch:

```sh
(cd ../ssrf-study/checkout/libs/community && \
  PYTHONPATH=../../../../safe-egress/src:../../../../safe-egress/examples/langchain-ssrf \
  poetry run python ../../../../safe-egress/examples/langchain-ssrf/check_release_default.py)
(cd ../ssrf-study/checkout/libs/community && \
  PYTHONPATH=../../../../langchain-community-fixed-0.2.9/libs/community:../../../../safe-egress/src:../../../../safe-egress/examples/langchain-ssrf \
  poetry run python ../../../../safe-egress/examples/langchain-ssrf/check_release_default.py)
```

Both commands use the vulnerable worktree's existing Poetry environment; the second puts the fixed package source first on `PYTHONPATH`. Expected: construction is allowed on 0.2.7 and refused by default on 0.2.9.

On the preparation host, invoking Poetry from the fixed worktree tried to create a separate Python 3.14 virtualenv and failed because the Poetry cache directory was not writable. Reusing the already provisioned environment while swapping the source path avoids that host-specific setup failure.

## Run the local SSRF and utility tests

The harness imports the real retriever and vulnerable loader source. It intercepts the controlled internal request before any socket opens. The utility case sends a synthetic public HTML response through aiohttp's real request/response parser and verifies indexing. No credentials, live URL, or external service is used.

```sh
(cd ../ssrf-study/checkout/libs/community && \
  PYTHONPATH=../../../../safe-egress/src:../../../../safe-egress/examples/langchain-ssrf \
  poetry run pytest -q ../../../../safe-egress/examples/langchain-ssrf/test_web_research_integration.py)
```

The six integration tests cover the vulnerable boundary, loopback blocking in the hardened aiohttp and Requests paths, and successful public-fixture indexing. The original checkout is not modified; the hardened loader is an isolated companion, not a patch to LangChain's installed loader.

The project’s existing `tests/unit_tests/retrievers/test_web_research.py` passed five tests on both tags in the prepared Poetry environment. Inspection shows these five tests cover only `QuestionListOutputParser`; they do not exercise `WebResearchRetriever`, `AsyncHtmlLoader`, or network fetching. They do not cover LangChain's full test suite or every possible application-specific fetch path.

To rerun the complete local matrix and write phase results plus a JSON report, use an environment that already has the Community test dependencies and Poetry:

```sh
PYTHONPATH=src poetry run python examples/langchain-ssrf/run_eval.py \
  --vulnerable ../ssrf-study/checkout \
  --fixed ../langchain-community-fixed-0.2.9
```

The runner does not install packages. It records the vulnerable and fixed Git revisions, builds both wheels, runs the five parser-only project tests on each revision, checks the default opt-in behavior for each source tree, and runs the six fixture-only SSRF/utility tests against both source revisions. The latest Python 3.11 rerun passed all eight phases in 4.703 seconds. The report and per-phase results are in [`results/continued-upload-limit-20261020/`](results/continued-upload-limit-20261020/). It used the existing `langchain-community-OHhycLXa-py3.11` Python environment; no dependencies were installed.

## Build smoke

Both Community source revisions also build as wheels without changing the worktrees or resolving dependencies. Run from each revision's `libs/community` directory:

```sh
POETRY_VIRTUALENVS_CREATE=false poetry build --format wheel \
  --output /tmp/langchain-community-0.2.7-wheel
POETRY_VIRTUALENVS_CREATE=false poetry build --format wheel \
  --output /tmp/langchain-community-0.2.9-wheel
```

On the preparation host, the ordinary command for 0.2.9 first tried to create a Python 3.14 virtualenv under a cache directory that was not writable. Setting `POETRY_VIRTUALENVS_CREATE=false` let Poetry's bundled build backend build directly without a new environment or package downloads. The resulting wheel hashes were `937932c983547320291df49a0f594f30a777c02f22529e3f74b2e219d9cb03f5` (0.2.7) and `673584f3ac23444442f36322b492968dfff6951415e544453a5965dd6efb22cb` (0.2.9). Each wheel was installed with `pip install --no-deps --no-index --target ...`; importing `langchain_community` and `WebResearchRetriever` resolved from the installed target. Running `check_release_default.py` against each installed wheel reproduced the default-construction difference: 0.2.7 allowed construction, while 0.2.9 refused it. The six local SSRF and utility integration tests also passed with the vulnerable 0.2.7 wheel first on `PYTHONPATH`. This is a packaging and behavior smoke check, not a full application build or test suite.
