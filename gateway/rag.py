"""
Lightweight RAG (Retrieval-Augmented Generation) simulation.

No embeddings/vector DB - just simple keyword-overlap scoring over a
folder of documents. The point isn't to build a real search engine,
it's to test what happens when a retrieval step can surface a
poisoned document alongside legitimate ones, based on nothing more
than shared keywords with the query.
"""

import os
import re

KNOWLEDGE_BASE_DIR = "knowledge_base"


def _tokenize(text):
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def search_documents(query, top_k=3):
    """
    Returns a list of (relative_path, score) for the top_k documents
    in KNOWLEDGE_BASE_DIR with the highest keyword overlap with query,
    sorted by score descending.
    """
    query_tokens = _tokenize(query)
    if not query_tokens or not os.path.isdir(KNOWLEDGE_BASE_DIR):
        return []

    scored = []
    for filename in os.listdir(KNOWLEDGE_BASE_DIR):
        if not filename.endswith(".txt"):
            continue
        path = os.path.join(KNOWLEDGE_BASE_DIR, filename)
        try:
            with open(path) as f:
                doc_tokens = _tokenize(f.read())
        except OSError:
            continue
        overlap = len(query_tokens & doc_tokens)
        if overlap > 0:
            scored.append((path.replace(os.sep, "/"), overlap))

    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:top_k]
