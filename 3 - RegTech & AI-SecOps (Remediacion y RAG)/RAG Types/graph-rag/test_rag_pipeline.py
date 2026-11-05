"""Graph-RAG Pipeline Test Suite.
Tests the determinism and extraction of the Graph Knowledge components.
"""

from rag_graph import EntityExtractor


def test_entity_extractor_acronyms() -> None:
    extractor = EntityExtractor()
    text = "Según el RGPD y la normativa NIS2, la empresa debe cumplir."
    entities = extractor.extract_entities(text)
    
    # Check that ACRONYM types are extracted
    names = [e["name"] for e in entities if e["type"] == "ACRONYM"]
    assert "RGPD" in names
    assert "NIS2" in names

def test_entity_extractor_metrics() -> None:
    extractor = EntityExtractor()
    text = "El plazo máximo es de 72 horas para notificar una brecha."
    entities = extractor.extract_entities(text)
    
    # Check that METRIC types are extracted
    names = [e["name"] for e in entities if e["type"] == "METRIC"]
    assert "72 horas" in names

def test_triplet_extraction() -> None:
    extractor = EntityExtractor()
    text = "DORA exige un límite de 24 horas. NIS2 prohíbe las conexiones inseguras."
    triplets = extractor.extract_triplets(text, chunk_id="test_chunk", source_file="test.md")
    
    relations = [t["relation"] for t in triplets]
    assert "REQUIERE" in relations or "TIENE_METRICA" in relations or "PROHIBE" in relations
