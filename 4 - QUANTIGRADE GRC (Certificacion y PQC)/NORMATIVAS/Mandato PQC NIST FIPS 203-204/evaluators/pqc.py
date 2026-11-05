#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pqc.py - Local Evaluator alias for Mandato PQC NIST FIPS 203-204.
Imports and exposes PQCEvaluator from src.evaluators.pqc.
"""

from __future__ import annotations
import sys
from pathlib import Path

# Add central compliance manager
COMP_MGR = Path(r"e:/PROYECTOS IA/PRODUCTION READY/100/GITHUB/QUANTIGRADE GRC")
if str(COMP_MGR) not in sys.path:
    sys.path.insert(0, str(COMP_MGR))

from src.evaluators.pqc import PQCEvaluator

__all__ = ["PQCEvaluator"]
