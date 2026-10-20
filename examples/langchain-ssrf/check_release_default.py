"""Black-box check of LangChain's WebResearchRetriever default behavior.

Run this script with the desired langchain-community checkout first on
``PYTHONPATH``. It constructs only local dummy objects and makes no request.
The vulnerable release accepts construction; the fixed release rejects it
unless its explicit dangerous-request opt-in is supplied.
"""

from __future__ import annotations

import json

from langchain_core.embeddings.fake import FakeEmbeddings
from langchain_core.language_models.fake import FakeListLLM
from langchain_core.vectorstores import InMemoryVectorStore
from langchain_community.retrievers.web_research import WebResearchRetriever
from langchain_community.utilities import GoogleSearchAPIWrapper


def main() -> None:
    try:
        WebResearchRetriever.from_llm(
            vectorstore=InMemoryVectorStore(FakeEmbeddings(size=2)),
            llm=FakeListLLM(responses=["1. harmless query"]),
            search=GoogleSearchAPIWrapper.construct(),
        )
    except ValueError as exc:
        print(json.dumps({"default_construction": "refused", "reason": str(exc)}))
    else:
        print(json.dumps({"default_construction": "allowed"}))


if __name__ == "__main__":
    main()
