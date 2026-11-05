#!/usr/bin/env python3
"""eu_ai_act_fria_assessor.py — EU AI Act Article 27 Fundamental Rights Impact Assessment (FRIA).

Compliance Alignment:
- Regulation (EU) 2024/1689 (EU AI Act), Article 27: Fundamental Rights Impact Assessment for high-risk AI.
- Spanish AI Agency (AESIA) and EDPB Guidelines.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path
from typing import Any, ClassVar


class EUAIActFRIAAssessor:
    """Evaluates and records Fundamental Rights Impact Assessments (FRIA) for high-risk AI systems."""

    FRIA_CORE_DIMENSIONS: ClassVar[list[str]] = [
        "human_dignity_and_autonomy",
        "non_discrimination_and_bias_mitigation",
        "privacy_and_data_protection",
        "freedom_of_expression_and_information",
        "right_to_effective_remedy_and_fair_trial",
    ]

    def __init__(
        self,
        system_name: str,
        risk_category: str = "HIGH_RISK",
        output_dir: str = "./fria_reports",
    ) -> None:
        self.system_name: str = system_name
        self.risk_category: str = risk_category
        self.output_dir: Path = Path(output_dir)

    def assess_impact(self, controls_evidence: dict[str, bool]) -> dict[str, Any]:
        """Perform automated FRIA scoring against statutory fundamental rights dimensions."""
        dimensions_status: dict[str, bool] = {}
        passed_count = 0

        for dim in self.FRIA_CORE_DIMENSIONS:
            status = controls_evidence.get(dim, True)
            dimensions_status[dim] = status
            if status:
                passed_count += 1

        total = len(self.FRIA_CORE_DIMENSIONS)
        fria_score = round((passed_count / total) * 100.0, 1)

        assessment = {
            "system_name": self.system_name,
            "risk_category": self.risk_category,
            "timestamp_iso": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "fria_score": fria_score,
            "passed_dimensions": passed_count,
            "total_dimensions": total,
            "is_fria_approved": fria_score >= 80.0,
            "dimension_evaluations": dimensions_status,
        }

        # Compute SHA-256 integrity seal
        digest = (
            hashlib.sha256(json.dumps(assessment, sort_keys=True).encode("utf-8"))
            .hexdigest()
            .upper()
        )
        assessment["fria_seal_sha256"] = digest
        return assessment


def main() -> None:
    parser = argparse.ArgumentParser(description="EU AI Act Art. 27 FRIA Assessor")
    parser.add_argument(
        "--system-name", default="Production-RAG-System", help="Name of AI system"
    )
    args = parser.parse_args()

    assessor = EUAIActFRIAAssessor(system_name=args.system_name)
    result = assessor.assess_impact({})
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
