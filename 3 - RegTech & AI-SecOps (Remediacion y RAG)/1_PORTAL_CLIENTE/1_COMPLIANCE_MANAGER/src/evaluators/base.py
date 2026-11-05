#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
base.py - Base data classes and abstractions for IT_COMPLIANCE_MANAGER evaluators.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

class RAGStatus(str, Enum):
    GREEN = "GREEN"   # High compliance, low risk
    AMBER = "AMBER"   # Moderate compliance, warning level
    RED = "RED"       # Low compliance, critical risk

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Finding:
    rule_id: str
    framework: str
    title: str
    description: str
    severity: Severity
    passed: bool
    evidence: str
    remediation_guidance: str
    iso27001_mapping: List[str] = field(default_factory=list)
    soc2_mapping: List[str] = field(default_factory=list)

@dataclass
class EvaluatorResult:
    framework_name: str
    compliance_score: float  # Percentage (0.0 to 100.0)
    rag_status: RAGStatus
    total_rules: int
    passed_rules: int
    failed_rules: int
    findings: List[Finding] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    remediation_hours_est: float = 0.0
    estimated_opex_impact_eur: float = 0.0

class BaseEvaluator:
    def __init__(self, target_path: str, company_name: str):
        self.target_path = target_path
        self.company_name = company_name

    def evaluate(self) -> EvaluatorResult:
        raise NotImplementedError("Subclasses must implement evaluate()")


if __name__ == '__main__':
    # Production entry point
    pass
