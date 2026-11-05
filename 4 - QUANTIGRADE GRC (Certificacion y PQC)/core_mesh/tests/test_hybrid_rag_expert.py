import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core_mesh.business_execution.hybrid_rag_expert import HybridRAGExpert

class TestHybridRAGExpert(unittest.TestCase):
    def setUp(self):
        self.expert = HybridRAGExpert()

    def test_graph_loading_and_entities(self):
        self.assertTrue(self.expert.grafo_path.exists())
        self.assertGreater(len(self.expert.triplets), 100)
        self.assertGreater(len(self.expert.entities), 50)

    def test_entity_extraction(self):
        query = "¿Qué medidas exige DORA y NIS2 sobre proveedores de nube TIC?"
        entities = self.expert.extract_query_entities(query)
        self.assertIn("dora", entities)
        self.assertIn("nis2", entities)

    def test_bfs_traversal(self):
        edges = self.expert.bfs_traverse(["dora"], depth=1)
        self.assertGreater(len(edges), 0)
        heads_and_tails = [e["head"].lower() for e in edges] + [e["tail"].lower() for e in edges]
        self.assertTrue(any("dora" in x for x in heads_and_tails))

    def test_query_regulatory_expert(self):
        res = self.expert.query_regulatory_expert("Requisitos de resiliencia operativa y pruebas TLPT bajo DORA")
        self.assertEqual(res["query"], "Requisitos de resiliencia operativa y pruebas TLPT bajo DORA")
        self.assertIn("dora", res["entities_found"])
        self.assertGreater(len(res["subgraph_triplets"]), 0)
        self.assertTrue(res["graph_available"])
        self.assertTrue(any(a["framework"] == "DORA" for a in res["supervisory_authorities"]))
        self.assertIn("EBA", str(res["supervisory_authorities"]))

    def test_fallback_nonexistent_graph(self):
        fallback_expert = HybridRAGExpert(grafo_path="/tmp/non_existent_graph_12345.json")
        res = fallback_expert.query_regulatory_expert("Consulta de prueba")
        self.assertEqual(res["total_subgraph_relations"], 0)
        self.assertFalse(res["graph_available"])
        self.assertIn("Quantigrade GCR", res["expert_dictamen"])

if __name__ == "__main__":
    unittest.main()
