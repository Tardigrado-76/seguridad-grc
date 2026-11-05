"""
NIS2 Engine — Directive (EU) 2022/2555
Covers: Art.21 (Security measures), Art.23 (Incident notification),
        Art.24 (Cybersecurity policies).
"""
from pathlib import Path
from engines.base_engine import BaseComplianceEngine


NIS2_CHECKS = [
    {"id": "NIS2-ART21-01", "article": "Art.21", "title": "Risk analysis and information security policies", "critical": True},
    {"id": "NIS2-ART21-02", "article": "Art.21", "title": "Incident handling procedures documented", "critical": True},
    {"id": "NIS2-ART21-03", "article": "Art.21", "title": "Business continuity plan (BCP) in place", "critical": True},
    {"id": "NIS2-ART21-04", "article": "Art.21", "title": "Supply chain security policy documented", "critical": True},
    {"id": "NIS2-ART21-05", "article": "Art.21", "title": "MFA / access control enforced", "critical": True},
    {"id": "NIS2-ART21-06", "article": "Art.21", "title": "Encryption at rest and in transit applied", "critical": True},
    {"id": "NIS2-ART23-01", "article": "Art.23", "title": "Early warning to CSIRT within 24h of major incident", "critical": True},
    {"id": "NIS2-ART23-02", "article": "Art.23", "title": "Incident notification within 72h", "critical": True},
    {"id": "NIS2-ART24-01", "article": "Art.24", "title": "Management body approved security policies", "critical": False},
]


class NIS2Engine(BaseComplianceEngine):
    ENGINE_NAME = "nis2"
    ENGINE_VERSION = "1.0.0"

    def run(self) -> dict:
        self.log.info("NIS2 audit started", target=str(self.target_path))
        target = self.target_path

        for check in NIS2_CHECKS:
            result = self._run_check(check, target)
            self.results.append(result)

        report = self._build_report()
        self.log.info("NIS2 audit complete", score=report["score"])
        return report

    def _run_check(self, check: dict, target: Path) -> dict:
        check_id = check["id"]
        found = False

        if "ART21-01" in check_id:
            found = any(target.rglob("*risk_analysis*")) or any(target.rglob("*security_policy*"))
        elif "ART21-02" in check_id:
            found = any(target.rglob("*incident_handling*")) or any(target.rglob("*incident_response*"))
        elif "ART21-03" in check_id:
            found = any(target.rglob("*bcp*")) or any(target.rglob("*business_continuity*"))
        elif "ART21-04" in check_id:
            found = any(target.rglob("*supply_chain*")) or any(target.rglob("*third_party*"))
        elif "ART21-05" in check_id:
            found = any(target.rglob("*mfa*")) or any(target.rglob("*access_control*"))
        elif "ART21-06" in check_id:
            found = any(target.rglob("*encrypt*")) or any(target.rglob("*tls*"))
        elif "ART23" in check_id:
            found = any(target.rglob("*notification*")) or any(target.rglob("*csirt*"))
        elif "ART24" in check_id:
            found = any(target.rglob("*management_policy*")) or any(target.rglob("*board_approval*"))

        status = "PASS" if found else "FAIL"
        return {
            "id": check_id,
            "article": check["article"],
            "title": check["title"],
            "critical": check["critical"],
            "success": found,
            "status": status,
        }