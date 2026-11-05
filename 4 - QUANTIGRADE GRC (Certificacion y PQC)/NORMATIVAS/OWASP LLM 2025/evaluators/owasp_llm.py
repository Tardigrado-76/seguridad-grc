#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
owasp_llm.py - Local Evaluator alias for OWASP LLM 2025.
Imports and exposes OWASPLLMEvaluator from src.evaluators.owasp_llm.
"""

from __future__ import annotations
import sys
from pathlib import Path

COMP_MGR = Path(r"e:/PROYECTOS IA/PRODUCTION READY/100/GITHUB/QUANTIGRADE GRC")
if str(COMP_MGR) not in sys.path:
    sys.path.insert(0, str(COMP_MGR))

from src.evaluators.owasp_llm import OWASPLLMEvaluator

__all__ = ["OWASPLLMEvaluator"]
