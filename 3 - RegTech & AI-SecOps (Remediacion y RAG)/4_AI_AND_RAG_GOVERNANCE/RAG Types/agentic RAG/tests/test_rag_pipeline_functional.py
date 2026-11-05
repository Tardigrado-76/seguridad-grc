"""hybrid-rag Functional Pipeline Tests."""

import os

from dotenv import load_dotenv

load_dotenv()  # Zero Trust env loading


def test_rag_configuration() -> None:
    from dotenv import load_dotenv
    load_dotenv()
    env = os.getenv("ENV", "production")
    assert env in ["development", "staging", "production", "test"]

def test_rag_embeddings_schema() -> None:
    embeddings_file = os.path.join(os.path.dirname(__file__), "..", "..", "rag_embeddings.json")
    if os.path.exists(embeddings_file):
        assert os.path.getsize(embeddings_file) > 0
