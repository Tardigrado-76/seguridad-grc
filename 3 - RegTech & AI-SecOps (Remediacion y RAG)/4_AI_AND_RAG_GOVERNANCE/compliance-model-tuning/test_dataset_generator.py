"""test_dataset_generator.py — Unit Tests for Fine-Tuning Dataset Generation & SFT.
==============================================================================
Pruebas de validación de sintaxis ChatML/Alpaca y pipeline de datos de fine-tuning.
"""

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).parent.resolve()
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

import json

from export_sovereign_model import generate_ollama_modelfile
from finetune_unsloth import SovereignModelTrainer
from generate_dataset import RAW_COMPLIANCE_KNOWLEDGE, ComplianceDatasetGenerator


def test_raw_knowledge_integrity() -> None:
    assert len(RAW_COMPLIANCE_KNOWLEDGE) >= 5
    for item in RAW_COMPLIANCE_KNOWLEDGE:
        assert "framework" in item
        assert "instruction" in item
        assert "output" in item
        assert len(item["output"]) > 50


def test_dataset_generation_and_splits(tmp_path) -> None:
    generator = ComplianceDatasetGenerator(output_dir=tmp_path)
    summary = generator.build_train_val_split(train_ratio=0.8)

    assert summary["total_samples"] >= 20
    assert summary["train_samples"] > summary["val_samples"]

    # Verificar formato ChatML
    train_chatml = tmp_path / "train_chatml.json"
    assert train_chatml.exists()

    with open(train_chatml, encoding="utf-8") as f:
        data = json.load(f)
        assert isinstance(data, list)
        assert "messages" in data[0]
        assert len(data[0]["messages"]) == 3
        assert data[0]["messages"][0]["role"] == "system"
        assert data[0]["messages"][1]["role"] == "user"
        assert data[0]["messages"][2]["role"] == "assistant"


def test_trainer_dry_run() -> None:
    trainer = SovereignModelTrainer()
    res = trainer.train(dry_run=True)
    assert res["status"] == "success"
    assert res["dry_run"] is True


def test_ollama_modelfile_generation(tmp_path) -> None:
    modelfile = generate_ollama_modelfile(output_dir=tmp_path)
    assert modelfile.exists()
    content = modelfile.read_text(encoding="utf-8")
    assert "FROM ./sovereign-compliance-8b.Q4_K_M.gguf" in content
    assert "EU AI Act" in content
