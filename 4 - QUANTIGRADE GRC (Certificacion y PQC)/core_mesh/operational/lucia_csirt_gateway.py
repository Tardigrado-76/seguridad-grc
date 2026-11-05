"""
LUCIA CSIRT Gateway for Quantigrade GCR.
Standardized incident reporting to CCN-CERT / INCIBE-CERT under NIS2 Art. 23 & Guía CCN-STIC 817.
Supports mandatory phases (24h/72h/1m) and STIX 2.1 JSON bundle serialization.
"""
import datetime
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IncidentNotificationPhase(str, Enum):
    EARLY_WARNING_24H = "EARLY_WARNING_24H"
    INCIDENT_NOTIFICATION_72H = "INCIDENT_NOTIFICATION_72H"
    INTERIM_REPORT = "INTERIM_REPORT"
    FINAL_REPORT_1M = "FINAL_REPORT_1M"


@dataclass
class LuciaNotificationPackage:
    incident_id: str
    phase: IncidentNotificationPhase
    lucia_format: dict[str, Any]
    stix_bundle: dict[str, Any]
    merkle_sha256: str
    timestamp_utc: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class LuciaCsirtGateway:
    """
    Integrates Quantigrade GCR with the National CSIRT network (CCN-CERT / INCIBE).
    Generates structured notifications compliant with LUCIA and STIX 2.1 specifications.
    """

    def __init__(self, csirt_name: str = "CCN-CERT", entity_tax_id: str = "A-28000000", entity_name: str = "Entidad Sujeta NIS2 / ENS"):
        self.csirt_name = csirt_name
        self.entity_tax_id = entity_tax_id
        self.entity_name = entity_name

    def build_stix_bundle(self, incident_data: dict[str, Any]) -> dict[str, Any]:
        """Serializes an incident into an OASIS STIX 2.1 compliant JSON bundle."""
        bundle_id = f"bundle--{uuid.uuid4()}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        identity_id = f"identity--{uuid.uuid4()}"
        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": self.entity_name,
            "identity_class": "organization",
            "contact_information": f"NIF: {self.entity_tax_id} | CSIRT Destino: {self.csirt_name}",
        }

        incident_id_stix = f"incident--{uuid.uuid4()}"
        incident_obj = {
            "type": "incident",
            "spec_version": "2.1",
            "id": incident_id_stix,
            "created": now,
            "modified": now,
            "name": incident_data.get("incident_id", "INCIDENT-001"),
            "description": incident_data.get("description", "Incidente de ciberseguridad notificado a CSIRT"),
            "confidence": 90,
            "created_by_ref": identity_id,
            "external_references": [
                {
                    "source_name": "LUCIA-CCN-CERT",
                    "description": "Notificacion obligatoria bajo Directiva NIS2 y Guia CCN-STIC 817",
                }
            ],
        }

        objects = [identity_obj, incident_obj]

        for ioc in incident_data.get("iocs", []):
            indicator_id = f"indicator--{uuid.uuid4()}"
            indicator_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now,
                "modified": now,
                "name": f"IoC {ioc}",
                "pattern": f"[network-traffic:dst_ref.value = '{ioc}']" if "." in ioc else f"[file:name = '{ioc}']",
                "pattern_type": "stix",
                "valid_from": now,
            }
            objects.append(indicator_obj)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

    def generate_notification(
        self,
        phase: IncidentNotificationPhase,
        incident_data: dict[str, Any],
    ) -> LuciaNotificationPackage:
        """
        Generates official LUCIA JSON notification for CCN-CERT along with STIX 2.1 bundle.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident_id = incident_data.get("incident_id", f"INC-{uuid.uuid4().hex[:8].upper()}")

        lucia_format: dict[str, Any] = {
            "fase": "ALERTA_TEMPRANA_24H" if phase == IncidentNotificationPhase.EARLY_WARNING_24H else (
                "NOTIFICACION_72H" if phase == IncidentNotificationPhase.INCIDENT_NOTIFICATION_72H else "INFORME_FINAL_1M"
            ),
            "id_incidente_notificador": incident_id,
            "fecha_notificacion_utc": now,
            "csirt_destino": self.csirt_name,
            "entidad_notificadora": {
                "nombre": self.entity_name,
                "nif": self.entity_tax_id,
                "clasificacion_nis2": incident_data.get("entity_type", "ENTIDAD_ESENCIAL"),
            },
            "sospecha_acto_ilicito": incident_data.get("suspected_unlawful", True),
            "impacto_transfronterizo": incident_data.get("potential_cross_border_impact", False),
            "servicios_afectados": incident_data.get("affected_services", ["Sistemas TIC"]),
        }

        if phase in (IncidentNotificationPhase.INCIDENT_NOTIFICATION_72H, IncidentNotificationPhase.FINAL_REPORT_1M):
            lucia_format["evaluacion_inicial"] = {
                "severidad": incident_data.get("severity", "HIGH"),
                "usuarios_afectados_estimados": incident_data.get("affected_users_count", 0),
                "ttps": incident_data.get("ttps", []),
                "iocs": incident_data.get("iocs", []),
            }

        if phase == IncidentNotificationPhase.FINAL_REPORT_1M:
            lucia_format["informe_cierre"] = {
                "causa_raiz": incident_data.get("root_cause", "Explotacion de vulnerabilidad no mitigada"),
                "medidas_mitigacion_aplicadas": incident_data.get("mitigations", ["Aislamiento perimetral y parcheo"]),
                "impacto_economico_estimado_eur": incident_data.get("financial_impact_eur", 0.0),
            }

        # Build STIX bundle
        stix_bundle = self.build_stix_bundle(incident_data)

        # Hash calculation for Merkle Bunker ledger
        serialized_payload = json.dumps(lucia_format, sort_keys=True).encode("utf-8")
        merkle_sha256 = hashlib.sha256(serialized_payload).hexdigest()

        return LuciaNotificationPackage(
            incident_id=incident_id,
            phase=phase,
            lucia_format=lucia_format,
            stix_bundle=stix_bundle,
            merkle_sha256=merkle_sha256,
            timestamp_utc=now,
        )
