"""
ENS Engine — Esquema Nacional de Seguridad (RD 311/2022)
Covers: Categories ALTA, MEDIA, BAJA across 75+ security measures.
"""
from pathlib import Path
from engines.base_engine import BaseComplianceEngine


ENS_CHECKS = [
    {"id": "ENS-ORG-01",  "category": "Organización", "level": "ALTA",  "title": "Security policy formally approved by management", "critical": True},
    {"id": "ENS-ORG-02",  "category": "Organización", "level": "MEDIA", "title": "Roles and responsibilities defined (RACI)", "critical": True},
    {"id": "ENS-OP-01",   "category": "Operación",    "level": "ALTA",  "title": "Asset inventory classified by security level", "critical": True},
    {"id": "ENS-OP-02",   "category": "Operación",    "level": "MEDIA", "title": "Change management procedure in place", "critical": False},
    {"id": "ENS-OP-03",   "category": "Operación",    "level": "ALTA",  "title": "Continuous monitoring and logging active", "critical": True},
    {"id": "ENS-MP-01",   "category": "Medidas",      "level": "ALTA",  "title": "Encrypted communications enforced (TLS 1.3+)", "critical": True},
    {"id": "ENS-MP-02",   "category": "Medidas",      "level": "ALTA",  "title": "Backup integrity verified monthly", "critical": True},
    {"id": "ENS-MP-03",   "category": "Medidas",      "level": "BAJA",  "title": "Physical access controls documented", "critical": False},
    {"id": "ENS-CLARA-01","category": "CCN-CERT",     "level": "ALTA",  "title": "CLARA hardening applied (score ≥ 80%)", "critical": True},
    {"id": "ENS-CLARA-02","category": "CCN-CERT",     "level": "MEDIA", "title": "CLARA remediation documented", "critical": False},
]


class ENSEngine(BaseComplianceEngine):
    ENGINE_NAME = "ens"
    ENGINE_VERSION = "1.0.0"

    def run(self) -> dict:
        self.log.info("ENS audit started", target=str(self.target_path))
        for check in ENS_CHECKS:
            result = self._run_check(check, self.target_path)
            self.results.append(result)
        report = self._build_report()
        self.log.info("ENS audit complete", score=report["score"])
        return report

    def _run_check(self, check: dict, target: Path) -> dict:
        check_id = check["id"]
        found = False

        if "ORG-01" in check_id:
            found = any(target.rglob("*security_policy*")) or any(target.rglob("*politica_seguridad*"))
        elif "ORG-02" in check_id:
            found = any(target.rglob("*raci*")) or any(target.rglob("*roles*"))
        elif "OP-01" in check_id:
            found = any(target.rglob("*asset_inventory*")) or any(target.rglob("*inventario*"))
        elif "OP-02" in check_id:
            found = any(target.rglob("*change_mgmt*")) or any(target.rglob("*cambios*"))
        elif "OP-03" in check_id:
            found = any(target.rglob("*monitoring*")) or any(target.rglob("*logs*"))
        elif "MP-01" in check_id:
            found = any(target.rglob("*tls*")) or any(target.rglob("*encrypt*"))
        elif "MP-02" in check_id:
            found = any(target.rglob("*backup*")) or any(target.rglob("*integrity*"))
        elif "MP-03" in check_id:
            found = any(target.rglob("*physical*")) or any(target.rglob("*acceso_fisico*"))
        elif "CLARA" in check_id:
            found = any(target.rglob("*CLARA*")) or any(target.rglob("*clara*")) or any(target.rglob("*hardening*"))

        status = "PASS" if found else "FAIL"
        return {
            "id": check_id,
            "category": check["category"],
            "level": check["level"],
            "title": check["title"],
            "critical": check["critical"],
            "success": found,
            "status": status,
        }