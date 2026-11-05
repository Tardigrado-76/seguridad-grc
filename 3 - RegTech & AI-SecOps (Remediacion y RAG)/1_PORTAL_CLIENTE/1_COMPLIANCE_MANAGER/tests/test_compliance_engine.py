"""
Functional Tests for COMPLIANCE_MANAGER Engine.
Validates real evaluator instantiation, scoring execution, and environment configuration.
"""

import os
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.evaluators.dora import DORAEvaluator
from src.evaluators.nis2 import NIS2Evaluator
from src.evaluators.pqc import PQCEvaluator
from src.evaluators.base import RAGStatus


def test_compliance_evaluators_instantiation(tmp_path):
    """Verify core evaluators instantiate, evaluate, and produce structured findings."""
    dora = DORAEvaluator(str(tmp_path), "Test Corp").evaluate()
    assert dora.framework_name == "DORA"
    assert dora.total_rules == 5
    assert dora.rag_status in [RAGStatus.RED, RAGStatus.AMBER, RAGStatus.GREEN]
    assert isinstance(dora.compliance_score, float)
    assert len(dora.findings) == 5

    nis2 = NIS2Evaluator(str(tmp_path), "Test Corp").evaluate()
    assert nis2.framework_name == "NIS2"
    assert nis2.total_rules == 4
    assert len(nis2.findings) == 4

    pqc = PQCEvaluator(str(tmp_path), "Test Corp").evaluate()
    assert pqc.framework_name == "Mandato PQC NIST FIPS 203-204"
    assert pqc.total_rules == 4
    assert len(pqc.findings) == 4


def test_environment_variables():
    """Verify workspace root configuration is valid and resolves to an existing directory."""
    workspace = os.getenv("WORKSPACE_ROOT", ".")
    path = Path(workspace).resolve()
    assert path.exists()
    assert path.is_dir()
