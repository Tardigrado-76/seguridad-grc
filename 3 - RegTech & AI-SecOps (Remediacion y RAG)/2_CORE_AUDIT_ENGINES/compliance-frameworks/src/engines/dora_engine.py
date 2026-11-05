"""
DORA Engine — Regulation (EU) 2022/2554
Covers: Art.6 (ICT Risk Mgmt), Art.17 (Classification), Art.18 (Reporting),
        Art.28 (Supply Chain), Art.30 (TLPT).
"""
from pathlib import Path
from engines.base_engine import BaseComplianceEngine


DORA_CHECKS = [
    {"id": "DORA-ART6-01",  "article": "Art.6",  "title": "ICT Risk Management Framework documented", "critical": True},
    {"id": "DORA-ART6-02",  "article": "Art.6",  "title": "Asset inventory maintained and updated", "critical": True},
    {"id": "DORA-ART17-01", "article": "Art.17", "title": "Incident classification criteria defined", "critical": True},
    {"id": "DORA-ART17-02", "article": "Art.17", "title": "Major incident escalation procedure exists", "critical": True},
    {"id": "DORA-ART18-01", "article": "Art.18", "title": "Initial incident report within 4 hours", "critical": True},
    {"id": "DORA-ART18-02", "article": "Art.18", "title": "Final incident report within 30 days", "critical": False},
    {"id": "DORA-ART28-01", "article": "Art.28", "title": "Third-party ICT providers register maintained", "critical": True},
    {"id": "DORA-ART28-02", "article": "Art.28", "title": "Contractual clauses cover data access and audit rights", "critical": True},
    {"id": "DORA-ART30-01", "article": "Art.30", "title": "TLPT threat intelligence scope defined", "critical": False},
    {"id": "DORA-ART30-02", "article": "Art.30", "title": "Penetration testing conducted annually", "critical": False},
]


class DORAEngine(BaseComplianceEngine):
    ENGINE_NAME = "dora"
    ENGINE_VERSION = "1.0.0"

    def run(self) -> dict:
        self.log.info("DORA audit started", target=str(self.target_path))
        target = self.target_path

        for check in DORA_CHECKS:
            result = self._run_check(check, target)
            self.results.append(result)

        report = self._build_report()
        self.log.info(
            "DORA audit complete",
            score=report["score"],
            passed=report["passed"],
            total=report["total"],
        )
        return report

    def _run_check(self, check: dict, target: Path) -> dict:
        """
        Heuristic checks against target directory.
        In production: connect to CI/CD APIs, Git history, ITSM.
        """
        check_id = check["id"]
        found = False

        # Heuristic: look for evidence files/patterns
        if "ART6" in check_id:
            found = any(target.rglob("*risk_management*")) or any(target.rglob("*ict_risk*"))
        elif "ART17" in check_id:
            found = any(target.rglob("*incident_classif*")) or any(target.rglob("*incident_policy*"))
        elif "ART18" in check_id:
            found = any(target.rglob("*incident_report*")) or any(target.rglob("*reporting*"))
        elif "ART28" in check_id:
            found = any(target.rglob("*third_party*")) or any(target.rglob("*supplier*"))
        elif "ART30" in check_id:
            found = any(target.rglob("*tlpt*")) or any(target.rglob("*pentest*"))

        status = "PASS" if found else "FAIL"
        self.log.debug(f"Check {check_id}", status=status)
        return {
            "id": check_id,
            "article": check["article"],
            "title": check["title"],
            "critical": check["critical"],
            "success": found,
            "status": status,
        }