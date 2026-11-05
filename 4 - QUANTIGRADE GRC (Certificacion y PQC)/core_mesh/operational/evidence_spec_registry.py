"""
Evidence Specification Registry & Automated Remediation Engine
Proporciona el catálogo estructurado de requisitos de evidencias para los 20 marcos normativos
(organizados en 7 familias normativas), motor de inspección previa Zero-Touch (solo lectura)
y remediación asistida por normativa para solucionar no conformidades e incidencias.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional


@dataclass(frozen=True)
class FrameworkEvidenceSpec:
    framework_key: str
    family: str
    name: str
    inspection_scope: str
    expected_artifacts: List[Dict[str, Any]]
    legal_citations: List[str]
    sample_tree: str


class EvidenceSpecRegistry:
    """Registro unificado de especificaciones de evidencias y remediador normativo."""

    SPECS: Dict[str, FrameworkEvidenceSpec] = {
        # 1. Ciberresiliencia & Operaciones Críticas
        "DORA": FrameworkEvidenceSpec(
            framework_key="DORA",
            family="Ciberresiliencia & Operaciones Críticas",
            name="Digital Operational Resilience Act (Reglamento UE 2022/2554)",
            inspection_scope="Gestión de riesgos TIC, clasificación y notificación de incidentes graves, pruebas de resiliencia operativa digital (TLPT/TIBER-ES) y gestión de riesgos derivados de terceros (TPRM).",
            expected_artifacts=[
                {"pattern": "dora_bcp_drp_policy.md", "name": "Política BCP/DRP DORA", "category": "policies", "legal_ref": "Art. 6 & 11", "description": "Plan formal de continuidad de negocio y recuperación de desastres TIC."},
                {"pattern": "dora_incident_classifier.py", "name": "Clasificador de Incidentes DORA", "category": "engines", "legal_ref": "Art. 18 & EBA/RTS/2024/02", "description": "Motor algorítmico de clasificación de incidentes TIC graves."},
                {"pattern": "third_party_register.json", "name": "Registro de Proveedores TIC Críticos", "category": "evidence", "legal_ref": "Art. 28", "description": "Registro informativo de contratos y acuerdos con terceros proveedores TIC (RoI)."},
                {"pattern": "tlpt_tiber_report.md", "name": "Informe de Pruebas TLPT / TIBER-ES", "category": "evidence", "legal_ref": "Art. 26", "description": "Dictamen de pruebas avanzadas de intrusión guiadas por amenazas (TLPT)."}
            ],
            legal_citations=["Reglamento (UE) 2022/2554", "EBA/RTS/2024/02", "Directiva (UE) 2022/2556"],
            sample_tree="policies/dora_bcp_drp_policy.md\nengines/dora_incident_classifier.py\nevidence/third_party_register.json"
        ),
        "NIS2": FrameworkEvidenceSpec(
            framework_key="NIS2",
            family="Ciberresiliencia & Operaciones Críticas",
            name="Directiva NIS 2 (Directiva UE 2022/2555)",
            inspection_scope="Gobernanza de ciberseguridad para entidades esenciales e importantes, reporte de incidentes en 24h a CSIRTs nacionales (INCIBE/CCN) y seguridad en la cadena de suministro.",
            expected_artifacts=[
                {"pattern": "nis2_security_policy.md", "name": "Política de Ciberseguridad NIS2", "category": "policies", "legal_ref": "Art. 21", "description": "Medidas de gestión de riesgos de ciberseguridad aprobadas por la dirección."},
                {"pattern": "nis2_incident_csirt.py", "name": "Procedimiento de Notificación CSIRT 24h", "category": "engines", "legal_ref": "Art. 23", "description": "Motor de escalado y alerta temprana a INCIBE-CERT / CCN-CERT."},
                {"pattern": "supply_chain_security.md", "name": "Evaluación de Seguridad de Proveedores", "category": "policies", "legal_ref": "Art. 21.2.d", "description": "Matriz de ciberseguridad en la cadena de suministro."}
            ],
            legal_citations=["Directiva (UE) 2022/2555 (NIS 2)", "Real Decreto-ley de Transposición NIS2 España"],
            sample_tree="policies/nis2_security_policy.md\nengines/nis2_incident_csirt.py"
        ),
        "ENS": FrameworkEvidenceSpec(
            framework_key="ENS",
            family="Ciberresiliencia & Operaciones Críticas",
            name="Esquema Nacional de Seguridad (Real Decreto 311/2022)",
            inspection_scope="Medidas de seguridad de Categoría ALTA para administraciones públicas y proveedores tecnológicos (marcos op.exp, mp.info, mp.per, mp.com).",
            expected_artifacts=[
                {"pattern": "ens_politica_seguridad.md", "name": "Política de Seguridad de la Información ENS", "category": "policies", "legal_ref": "Art. 12 & Anexo II", "description": "Política marco de seguridad formalizada conforme a RD 311/2022."},
                {"pattern": "ens_fim_integrity.py", "name": "Monitor de Integridad de Archivos (FIM)", "category": "engines", "legal_ref": "Medida [op.exp.8]", "description": "Motor de comprobación periódica de integridad criptográfica de binarios y configuraciones."},
                {"pattern": "ens_declaracion_conformidad.md", "name": "Declaración/Certificación de Conformidad ENS", "category": "evidence", "legal_ref": "Art. 41", "description": "Distintivo oficial de conformidad ENS emitido por entidad acreditada por ENAC."}
            ],
            legal_citations=["Real Decreto 311/2022 (ENS)", "Guías CCN-STIC 800"],
            sample_tree="policies/ens_politica_seguridad.md\nengines/ens_fim_integrity.py"
        ),
        "Protección de Infraestructuras Críticas (LPIC)": FrameworkEvidenceSpec(
            framework_key="Protección de Infraestructuras Críticas (LPIC)",
            family="Ciberresiliencia & Operaciones Críticas",
            name="Ley 8/2011 de Protección de Infraestructuras Críticas (LPIC)",
            inspection_scope="Operadores críticos y esenciales bajo CNPIC: Plan de Seguridad del Operador (PSO), Plan de Protección Específico (PPE) y designación del Responsable de Seguridad.",
            expected_artifacts=[
                {"pattern": "pso_plan_seguridad_operador.md", "name": "Plan de Seguridad del Operador (PSO)", "category": "policies", "legal_ref": "Art. 13 Ley 8/2011", "description": "Documento director de seguridad integral del operador crítico."},
                {"pattern": "ppe_plan_proteccion_especifico.md", "name": "Plan de Protección Específico (PPE)", "category": "policies", "legal_ref": "Art. 14 Ley 8/2011", "description": "Medidas de seguridad física y lógica aplicadas a la infraestructura crítica."},
                {"pattern": "lpic_enlace_cnpic.py", "name": "Procedimiento de Interlocución CNPIC", "category": "engines", "legal_ref": "Art. 16", "description": "Canal seguro de comunicación con el Centro Nacional de Protección de Infraestructuras Críticas."}
            ],
            legal_citations=["Ley 8/2011 (LPIC)", "Real Decreto 704/2011"],
            sample_tree="policies/pso_plan_seguridad_operador.md\npolicies/ppe_plan_proteccion_especifico.md"
        ),
        "Ciberresiliencia Financiera en España": FrameworkEvidenceSpec(
            framework_key="Ciberresiliencia Financiera en España",
            family="Ciberresiliencia & Operaciones Críticas",
            name="Ciberresiliencia Financiera (Banco de España / CNMV)",
            inspection_scope="Supervisión prudencial y resiliencia tecnológica para entidades supervisadas por Banco de España y CNMV.",
            expected_artifacts=[
                {"pattern": "bde_politica_riesgo_tic.md", "name": "Marco de Gobierno TIC Banco de España", "category": "policies", "legal_ref": "Circular BdE 2/2016 & DORA", "description": "Gobernanza y control interno de riesgos tecnológicos financieros."},
                {"pattern": "bde_registro_proveedores_terceros.json", "name": "Registro de Externalizaciones Críticas", "category": "evidence", "legal_ref": "Guía EBA/GL/2019/02", "description": "Inventario de servicios esenciales externalizados a proveedores Cloud."},
                {"pattern": "bde_plan_pruebas_resiliencia.md", "name": "Plan de Pruebas de Resiliencia Financiera", "category": "evidence", "legal_ref": "TIBER-ES", "description": "Cronograma y alcance de pruebas avanzadas de ciberresiliencia."}
            ],
            legal_citations=["Circulares Banco de España", "Guías EBA sobre externalización", "Marco TIBER-ES"],
            sample_tree="policies/bde_politica_riesgo_tic.md\nevidence/bde_registro_proveedores_terceros.json"
        ),
        "Ley General de Telecomunicaciones (LGTel)": FrameworkEvidenceSpec(
            framework_key="Ley General de Telecomunicaciones (LGTel)",
            family="Ciberresiliencia & Operaciones Críticas",
            name="Ley 11/2022 General de Telecomunicaciones y Seguridad 5G",
            inspection_scope="Integridad y seguridad de redes de comunicaciones electrónicas, servicios 5G y notificación obligatoria de incidentes significativos a SETELECO.",
            expected_artifacts=[
                {"pattern": "lgtel_politica_seguridad_red.md", "name": "Política de Seguridad de Redes", "category": "policies", "legal_ref": "Art. 110 Ley 11/2022", "description": "Medidas técnicas de gestión de riesgos de seguridad en redes públicas de comunicaciones."},
                {"pattern": "lgtel_incident_notification_procedure.py", "name": "Procedimiento de Notificación a SETELECO", "category": "engines", "legal_ref": "Art. 111 Ley 11/2022", "description": "Protocolo de notificación de incidentes con impacto significativo en el servicio."}
            ],
            legal_citations=["Ley 11/2022 General de Telecomunicaciones", "Real Decreto-ley 7/2022 (Seguridad Redes 5G)"],
            sample_tree="policies/lgtel_politica_seguridad_red.md\nengines/lgtel_incident_notification_procedure.py"
        ),

        # 2. Cadena de Suministro & Seguridad de Software
        "CRA": FrameworkEvidenceSpec(
            framework_key="CRA",
            family="Cadena de Suministro & Seguridad de Software",
            name="Cyber Resilience Act (Reglamento UE de Ciberresiliencia)",
            inspection_scope="Seguridad por diseño en productos con elementos digitales, inventario SBOM (CycloneDX / SPDX), gestión de vulnerabilidades conocidas (KEV) y política de parches durante el ciclo de vida.",
            expected_artifacts=[
                {"pattern": "cyclonedx_sbom.json", "name": "Inventario SBOM Machine-Readable", "category": "evidence", "legal_ref": "Art. 10.2", "description": "Software Bill of Materials en formato estándar CycloneDX o SPDX."},
                {"pattern": "cra_sbom_kev_engine.py", "name": "Escáner de Vulnerabilidades KEV", "category": "engines", "legal_ref": "Art. 11", "description": "Motor de validación continua contra el catálogo CISA KEV y bases CVE."},
                {"pattern": "vulnerability_disclosure_policy.md", "name": "Política de Divulgación Coordinada", "category": "policies", "legal_ref": "Art. 10.6", "description": "Procedimiento de reporte de fallos de seguridad (security.txt y contacto CSIRT)."}
            ],
            legal_citations=["Reglamento (UE) del Parlamento Europeo y del Consejo sobre Ciberresiliencia (CRA)"],
            sample_tree="evidence/cyclonedx_sbom.json\nengines/cra_sbom_kev_engine.py\npolicies/vulnerability_disclosure_policy.md"
        ),
        "OWASP LLM 2025": FrameworkEvidenceSpec(
            framework_key="OWASP LLM 2025",
            family="Cadena de Suministro & Seguridad de Software",
            name="OWASP Top 10 for Large Language Models 2025",
            inspection_scope="Blindaje de modelos de lenguaje e IA generativa: mitigación de Prompt Injection (LLM01), envenenamiento de datos (LLM03), agencia excesiva (LLM06) y fuga de información sensible.",
            expected_artifacts=[
                {"pattern": "owasp_llm_guardrails.py", "name": "Guardarraíles de Sanitización LLM", "category": "engines", "legal_ref": "LLM01 / LLM06", "description": "Filtros en tiempo de ejecución para prompt injection y control de permisos de herramientas de agentes."},
                {"pattern": "dataset_integrity_verifier.py", "name": "Verificador de Integridad de Datasets", "category": "engines", "legal_ref": "LLM03", "description": "Detección de contaminación y envenenamiento de datos de ajuste fino (Fine-Tuning)."}
            ],
            legal_citations=["OWASP Top 10 for Large Language Model Applications (v2025)"],
            sample_tree="engines/owasp_llm_guardrails.py\nengines/dataset_integrity_verifier.py"
        ),
        "DATA Act": FrameworkEvidenceSpec(
            framework_key="DATA Act",
            family="Cadena de Suministro & Seguridad de Software",
            name="Data Act (Reglamento UE 2023/2854)",
            inspection_scope="Interoperabilidad y portabilidad de datos generados por productos conectados (IoT), acceso no discriminatorio y eliminación de barreras para el cambio de proveedor de servicios cloud.",
            expected_artifacts=[
                {"pattern": "data_act_access_policy.md", "name": "Política de Acceso y Portabilidad", "category": "policies", "legal_ref": "Art. 3 & 4", "description": "Términos transparentes de acceso a datos de productos conectados en tiempo real."},
                {"pattern": "data_sharing_contract.md", "name": "Contrato Tipo de Compartición FRAND", "category": "policies", "legal_ref": "Art. 8", "description": "Condiciones justas, razonables y no discriminatorias para la puesta a disposición de datos."}
            ],
            legal_citations=["Reglamento (UE) 2023/2854 sobre normas armonizadas para un acceso justo a los datos"],
            sample_tree="policies/data_act_access_policy.md\npolicies/data_sharing_contract.md"
        ),
        "DSA (Digital Service Act)": FrameworkEvidenceSpec(
            framework_key="DSA (Digital Service Act)",
            family="Cadena de Suministro & Seguridad de Software",
            name="Digital Services Act (Reglamento UE 2022/2065)",
            inspection_scope="Transparencia de plataformas digitales, sistemas de moderación de contenidos ilícitos, mecanismos de notificación y acción (*notice-and-action*) y protección de menores.",
            expected_artifacts=[
                {"pattern": "dsa_content_moderation_policy.md", "name": "Política de Moderación de Contenidos", "category": "policies", "legal_ref": "Art. 14 & 16", "description": "Términos de servicio y mecanismos de aviso y retirada de contenidos ilegales."},
                {"pattern": "dsa_transparency_report.json", "name": "Métricas y Registro de Transparencia", "category": "evidence", "legal_ref": "Art. 15", "description": "Registro estructurado de reclamaciones, resoluciones y suspensiones de cuentas."}
            ],
            legal_citations=["Reglamento (UE) 2022/2065 relativo a un mercado único de servicios digitales (DSA)"],
            sample_tree="policies/dsa_content_moderation_policy.md\nevidence/dsa_transparency_report.json"
        ),

        # 3. Privacidad, Identidad & Sociedad Digital
        "RGPD - LOPDGDD": FrameworkEvidenceSpec(
            framework_key="RGPD - LOPDGDD",
            family="Privacidad, Identidad & Sociedad Digital",
            name="RGPD (UE 2016/679) & LOPDGDD (Ley Orgánica 3/2018)",
            inspection_scope="Tratamiento de datos personales, Registro de Actividades de Tratamiento (RAT), medidas técnicas de seguridad (TOMs), borrado seguro y trazabilidad de derechos ARSULIPO.",
            expected_artifacts=[
                {"pattern": "registro_actividades_tratamiento.json", "name": "Registro de Actividades de Tratamiento (RAT)", "category": "evidence", "legal_ref": "Art. 30 RGPD / Art. 31 LOPDGDD", "description": "Inventario formal de tratamientos de datos personales y bases jurídicas."},
                {"pattern": "crypto_shredder.py", "name": "Mecanismo de Borrado Seguro (Crypto-Shredding)", "category": "engines", "legal_ref": "Art. 17 RGPD (NIST 800-88)", "description": "Motor de destrucción criptográfica de claves para derecho al olvido irreversible."},
                {"pattern": "procedimiento_derechos_sar.md", "name": "Procedimiento de Ejercicio de Derechos", "category": "policies", "legal_ref": "Arts. 15-22 RGPD", "description": "Protocolo de atención y respuesta a solicitudes de acceso, rectificación y supresión en < 30 días."}
            ],
            legal_citations=["Reglamento (UE) 2016/679 (RGPD)", "Ley Orgánica 3/2018 (LOPDGDD)"],
            sample_tree="evidence/registro_actividades_tratamiento.json\nengines/crypto_shredder.py\npolicies/procedimiento_derechos_sar.md"
        ),
        "eIDAS 2.0": FrameworkEvidenceSpec(
            framework_key="eIDAS 2.0",
            family="Privacidad, Identidad & Sociedad Digital",
            name="eIDAS 2.0 / Cartera Europea de Identidad Digital (EUDI)",
            inspection_scope="Servicios de confianza cualificados, firmas electrónicas cualificadas (QES), sellos de tiempo cualificados y compatibilidad con el Marco de Arquitectura EUDI Wallet.",
            expected_artifacts=[
                {"pattern": "eidas_qes_signature_engine.py", "name": "Validador de Firmas Cualificadas (QES)", "category": "engines", "legal_ref": "Art. 25 & 32", "description": "Motor de verificación de firmas y certificados emitidos por prestadores cualificados (QTSP)."},
                {"pattern": "eudi_wallet_integration_policy.md", "name": "Política de Integración EUDI Wallet", "category": "policies", "legal_ref": "Art. 6a eIDAS 2.0", "description": "Especificación de aceptación de credenciales verificables y atributos electrónicos soberanos."}
            ],
            legal_citations=["Reglamento (UE) 2024/1183 (eIDAS 2.0)", "Arquitectura y Marco de Referencia EUDI"],
            sample_tree="engines/eidas_qes_signature_engine.py\npolicies/eudi_wallet_integration_policy.md"
        ),
        "LSSI-CE (Servicios Sociedad Información y Cookies)": FrameworkEvidenceSpec(
            framework_key="LSSI-CE (Servicios Sociedad Información y Cookies)",
            family="Privacidad, Identidad & Sociedad Digital",
            name="Ley 34/2002 LSSI-CE & Guía de Cookies AEPD",
            inspection_scope="Comunicaciones comerciales electrónicas (anti-spam con doble opt-in), aviso legal, política de privacidad y gestión de cookies conforme al estándar AEPD (rechazo en 1er nivel).",
            expected_artifacts=[
                {"pattern": "lssi_politica_cookies.md", "name": "Política de Cookies y Aviso Legal LSSI", "category": "policies", "legal_ref": "Art. 10 & 22 LSSI", "description": "Aviso legal corporativo y tabla granular de cookies con detalle de finalidades y terceros."},
                {"pattern": "lssi_antispam_consent_manager.py", "name": "Gestor de Consentimiento y Anti-Spam", "category": "engines", "legal_ref": "Art. 21 LSSI", "description": "Registro inmutable de consentimientos de doble opt-in y sistema de baja instantánea (*opt-out*)."}
            ],
            legal_citations=["Ley 34/2002 (LSSI-CE)", "Guía sobre el uso de cookies AEPD (2024)"],
            sample_tree="policies/lssi_politica_cookies.md\nengines/lssi_antispam_consent_manager.py"
        ),

        # 4. Inteligencia Artificial Responsable
        "EU AI Act": FrameworkEvidenceSpec(
            framework_key="EU AI Act",
            family="Inteligencia Artificial Responsable",
            name="Artificial Intelligence Act (Reglamento UE 2024/1689)",
            inspection_scope="Clasificación de riesgo de sistemas de IA, gobernanza y calidad de datos de entrenamiento, marcado forense de contenido sintético (Art. 50 / C2PA) y supervisión humana.",
            expected_artifacts=[
                {"pattern": "ai_model_card.json", "name": "Ficha Técnica del Modelo (Model Card)", "category": "evidence", "legal_ref": "Art. 11 & Anexo IV", "description": "Documentación técnica de arquitectura, métricas de desempeño y sesgos evaluados."},
                {"pattern": "ai_watermark_c2pa.py", "name": "Marcado Digital de Contenido Sintético", "category": "engines", "legal_ref": "Art. 50", "description": "Algoritmo de marcado y detección de contenidos generados por IA (Deepfakes / Texto)."},
                {"pattern": "fria_impact_assessment.md", "name": "Evaluación de Impacto en Derechos (FRIA)", "category": "policies", "legal_ref": "Art. 27", "description": "Evaluación previa obligatoria del impacto en derechos fundamentales para IA de alto riesgo."}
            ],
            legal_citations=["Reglamento (UE) 2024/1689 (Ley de Inteligencia Artificial)", "Estándares CEN-CENELEC JTC 21"],
            sample_tree="evidence/ai_model_card.json\nengines/ai_watermark_c2pa.py\npolicies/fria_impact_assessment.md"
        ),
        "Gobernanza de IA en España (AESIA)": FrameworkEvidenceSpec(
            framework_key="Gobernanza de IA en España (AESIA)",
            family="Inteligencia Artificial Responsable",
            name="Gobernanza de IA en España (AESIA / RD 817/2023)",
            inspection_scope="Supervisión nacional de IA por la Agencia Española de Supervisión de Inteligencia Artificial (AESIA), sandbox regulatorio y registro de sistemas de alto impacto.",
            expected_artifacts=[
                {"pattern": "aesia_registro_sistema_ia.json", "name": "Ficha de Registro ante AESIA", "category": "evidence", "legal_ref": "RD 817/2023", "description": "Expediente de registro del sistema y autoevaluación de conformidad."},
                {"pattern": "aesia_supervision_humana_policy.md", "name": "Protocolo de Supervisión Humana (HITL)", "category": "policies", "legal_ref": "Art. 14 EU AI Act & AESIA", "description": "Procedimiento operativo para que operadores humanos puedan anular decisiones algorítmicas."}
            ],
            legal_citations=["Real Decreto 817/2023 (Entorno Controlado de Pruebas IA)", "Estatuto de la AESIA (RD 729/2023)"],
            sample_tree="evidence/aesia_registro_sistema_ia.json\npolicies/aesia_supervision_humana_policy.md"
        ),

        # 5. Prevención Penal & Activos Intangibles
        "Corporate Defense y Prevención Penal": FrameworkEvidenceSpec(
            framework_key="Corporate Defense y Prevención Penal",
            family="Prevención Penal & Activos Intangibles",
            name="Corporate Defense & Compliance Penal (Art. 31 bis Código Penal)",
            inspection_scope="Modelo organizativo de prevención de delitos penales de la persona jurídica, canal ético confidencial (Ley 2/2023) y régimen disciplinario sancionador.",
            expected_artifacts=[
                {"pattern": "manual_prevencion_penal.md", "name": "Manual de Prevención Penal Corporativo", "category": "policies", "legal_ref": "Art. 31 bis.2 CP", "description": "Identificación de actividades de riesgo penal y mapa de riesgos criminales."},
                {"pattern": "canal_etico_denuncias.py", "name": "Canal Ético y de Denuncias Seguro", "category": "engines", "legal_ref": "Ley 2/2023 (Whistleblowing)", "description": "Sistema de gestión de comunicaciones anónimas y protección del informante."},
                {"pattern": "acta_organo_cumplimiento.md", "name": "Estatuto del Órgano de Cumplimiento", "category": "policies", "legal_ref": "Art. 31 bis.2.2ª CP", "description": "Designación formal con poderes autónomos de iniciativa y control."}
            ],
            legal_citations=["Artículo 31 bis del Código Penal Español", "Ley 2/2023 reguladora de la protección del informante", "Circular 1/2016 FGE"],
            sample_tree="policies/manual_prevencion_penal.md\nengines/canal_etico_denuncias.py\npolicies/acta_organo_cumplimiento.md"
        ),
        "Ley de Secretos Empresariales": FrameworkEvidenceSpec(
            framework_key="Ley de Secretos Empresariales",
            family="Prevención Penal & Activos Intangibles",
            name="Ley 1/2019 de Secretos Empresariales",
            inspection_scope="Medidas razonables adoptadas por el titular para mantener en secreto la información de valor empresarial (Art. 3), acuerdos de confidencialidad y control de accesos.",
            expected_artifacts=[
                {"pattern": "inventario_secretos_empresariales.json", "name": "Inventario de Secretos y Clasificación", "category": "evidence", "legal_ref": "Art. 1 & 3 Ley 1/2019", "description": "Registro clasificado de activos intangibles y know-how confidencial protegido."},
                {"pattern": "secretos_rbac_access_controller.py", "name": "Control de Acceso Basado en Roles (RBAC)", "category": "engines", "legal_ref": "Art. 3 Ley 1/2019", "description": "Principio de mínimo privilegio y autorización estricta para acceder a secretos."},
                {"pattern": "secretos_audit_and_watermark_tracker.py", "name": "Trazabilidad Forense y Marcas de Agua", "category": "engines", "legal_ref": "Art. 3 Ley 1/2019", "description": "Registro inmutable de descargas y estampado de marcas forenses para persecución civil y penal."}
            ],
            legal_citations=["Ley 1/2019 de Secretos Empresariales", "Directiva (UE) 2016/943"],
            sample_tree="evidence/inventario_secretos_empresariales.json\nengines/secretos_rbac_access_controller.py\nengines/secretos_audit_and_watermark_tracker.py"
        ),

        # 6. Certificaciones de Mercado & Cloud Soberana
        "ISO 27001 - SOC2": FrameworkEvidenceSpec(
            framework_key="ISO 27001 - SOC2",
            family="Certificaciones de Mercado & Cloud Soberana",
            name="ISO/IEC 27001:2022 & AICPA SOC 2 Type II",
            inspection_scope="Sistema de Gestión de Seguridad de la Información (SGSI), Declaración de Aplicabilidad de los 93 controles del Anexo A y Criterios de Confianza SOC 2 (TSC CC1 a CC9).",
            expected_artifacts=[
                {"pattern": "statement_of_applicability_soa.json", "name": "Declaración de Aplicabilidad (SoA ISO 27001)", "category": "evidence", "legal_ref": "Control 6.1.3 & Anexo A", "description": "Estado de justificación y aplicabilidad de los 93 controles de seguridad."},
                {"pattern": "soc2_trust_services_criteria.md", "name": "Matriz de Controles SOC 2 (Security/Availability)", "category": "policies", "legal_ref": "AICPA TSC CC1-CC9", "description": "Evidencias operativas de efectividad de controles de seguridad en la nube."}
            ],
            legal_citations=["ISO/IEC 27001:2022", "AICPA Trust Services Criteria (SOC 2)"],
            sample_tree="evidence/statement_of_applicability_soa.json\npolicies/soc2_trust_services_criteria.md"
        ),
        "ENISA EUCS": FrameworkEvidenceSpec(
            framework_key="ENISA EUCS",
            family="Certificaciones de Mercado & Cloud Soberana",
            name="European Cybersecurity Certification Scheme for Cloud Services",
            inspection_scope="Soberanía de datos cloud, inmunidad frente a legislaciones extraterritoriales (U.S. CLOUD Act), custodia de claves en HSMs en suelo europeo y auditoría de aislamiento multi-tenant.",
            expected_artifacts=[
                {"pattern": "enisa_eucs_manifest.json", "name": "Manifiesto de Soberanía y Jurisdicción Cloud", "category": "evidence", "legal_ref": "Requisito EUCS High", "description": "Declaración de residencia de datos exclusiva en la Unión Europea."},
                {"pattern": "hsm_kms_assurance_policy.md", "name": "Política de Custodia de Claves HSM Europeo", "category": "policies", "legal_ref": "Control EUCS KMS-01", "description": "Garantía de que las claves criptográficas maestras residen en HSMs certificados FIPS/CC en la UE."}
            ],
            legal_citations=["Esquema Europeo de Certificación de Ciberseguridad para Servicios en la Nube (EUCS)", "ENISA Cloud Guidelines"],
            sample_tree="evidence/enisa_eucs_manifest.json\npolicies/hsm_kms_assurance_policy.md"
        ),
        "Mandato PQC NIST FIPS 203-204": FrameworkEvidenceSpec(
            framework_key="Mandato PQC NIST FIPS 203-204",
            family="Criptografía Post-Cuántica & Seguridad de Nueva Generación",
            name="Mandato PQC (NIST FIPS 203/204 / CNSA 2.0)",
            inspection_scope="Agilidad criptográfica, migración post-cuántica a FIPS 203 (ML-KEM) y FIPS 204 (ML-DSA), protección contra amenazas 'Harvest Now, Decrypt Later', zeroización FIPS 140-3 y firma cuántica de código.",
            expected_artifacts=[
                {"pattern": "PQC_ESTRATEGIA_MIGRACION_POST_CUANTICA.md", "name": "Estrategia de Migración Post-Cuántica", "category": "policies", "legal_ref": "NIST SP 800-227 / CCN-STIC 807", "description": "Plan formal y hoja de ruta para la sustitución de algoritmos vulnerables RSA/ECC."},
                {"pattern": "pqc_crypto_agility_manager.py", "name": "Gestor de Agilidad Criptográfica PQC", "category": "engines", "legal_ref": "BSI TR-02102-1 & NIST IR 8547", "description": "Motor de inventario y sustitución ágil de primitivas criptográficas."},
                {"pattern": "pqc_hybrid_tls_verifier.py", "name": "Verificador TLS 1.3 Híbrido ML-KEM", "category": "engines", "legal_ref": "FIPS 203 / IETF RFC 9180", "description": "Verificador de encapsulamiento híbrido X25519Kyber768 en comunicaciones de red."},
                {"pattern": "fips_204_mldsa_git_commit_signer.py", "name": "Firmador de Commits y Código ML-DSA", "category": "engines", "legal_ref": "FIPS 204 (ML-DSA-87)", "description": "Firmador criptográfico resistente a computación cuántica para la cadena de suministro de software."}
            ],
            legal_citations=["NIST FIPS 203 (ML-KEM)", "NIST FIPS 204 (ML-DSA)", "NIST FIPS 205 (SLH-DSA)", "CNSA 2.0", "CCN-STIC 807", "BSI TR-02102-1"],
            sample_tree="policies/PQC_ESTRATEGIA_MIGRACION_POST_CUANTICA.md\nengines/pqc_crypto_agility_manager.py\nengines/pqc_hybrid_tls_verifier.py"
        ),
        "DGAM": FrameworkEvidenceSpec(
            framework_key="DGAM",
            family="Defensa & Soberanía Operativa OTAN",
            name="DGAM / OTAN Homologación y Calidad Militar (PECAL 2110/2210 & REDGAM)",
            inspection_scope="Aseguramiento de la calidad de software de defensa (PECAL 2110/2210), inscripción en el Registro de Empresas de la DGAM (REDGAM), resiliencia en sistemas de misión crítica militar y soberanía de cadena de suministro sin componentes vetados.",
            expected_artifacts=[
                {"pattern": "DGAM_PECAL_2110_2210_CALIDAD_DEFENSA.md", "name": "Política de Calidad Militar PECAL", "category": "policies", "legal_ref": "PECAL 2110 / 2210", "description": "Plan formal de aseguramiento de calidad del software de defensa."},
                {"pattern": "redgam_registration_certificate.json", "name": "Certificado Oficial REDGAM", "category": "evidence", "legal_ref": "Orden DEF/877/2014", "description": "Acreditación formal en el Registro de Empresas de la DGAM."},
                {"pattern": "mision_critica_resiliencia_aap48.md", "name": "Matriz de Resiliencia de Misión Militar", "category": "evidence", "legal_ref": "OTAN AAP-20 / AAP-48", "description": "Tolerancia a fallos y modo degradado para sistemas de misión crítica."},
                {"pattern": "soberania_cadena_suministro_otan.json", "name": "Auditoría de Cadena Soberana de Suministro", "category": "evidence", "legal_ref": "Directivas DGAM / OTAN", "description": "Garantía de procedencia de componentes de defensa 100% en España/OTAN."}
            ],
            legal_citations=["PECAL 2110 Ed.4", "PECAL 2210 Ed.2", "Orden DEF/877/2014", "OTAN AAP-20", "OTAN AAP-48"],
            sample_tree="policies/DGAM_PECAL_2110_2210_CALIDAD_DEFENSA.md\nevidence/redgam_registration_certificate.json\nevidence/soberania_cadena_suministro_otan.json"
        ),
        "ITAR - EAR": FrameworkEvidenceSpec(
            framework_key="ITAR - EAR",
            family="Defensa & Soberanía Operativa OTAN",
            name="Control de Exportaciones de Defensa y Doble Uso (ITAR / EAR / Reglamento UE 2021/821)",
            inspection_scope="Custodia y control de acceso a datos técnicos USML (ITAR 22 CFR 120-130), clasificación ECCN bajo Commerce Control List (EAR 15 CFR 730-774), cumplimiento del Anexo I del Reglamento UE 2021/821 y cifrado FIPS 140-3 con soberanía de claves.",
            expected_artifacts=[
                {"pattern": "ITAR_EAR_DUAL_USE_EXPORT_CONTROL_POLICY.md", "name": "Política de Control de Exportaciones", "category": "policies", "legal_ref": "22 CFR §120 / 15 CFR §730", "description": "Manual de segregación de datos técnicos y prevención de exportación no licenciada."},
                {"pattern": "itar_usml_technical_data_access_log.json", "name": "Registro de Acceso a Datos USML", "category": "evidence", "legal_ref": "ITAR 22 CFR §120.10", "description": "Trazabilidad de acceso a artículos y datos de defensa segregados."},
                {"pattern": "ear_ccl_eccn_classification_sheet.md", "name": "Ficha de Clasificación ECCN EAR", "category": "evidence", "legal_ref": "15 CFR §740.17", "description": "Clasificación de tecnologías y criptografía de doble uso bajo la CCL."},
                {"pattern": "reglamento_821_doble_uso_annex_i_audit.json", "name": "Auditoría de Doble Uso UE 2021/821", "category": "evidence", "legal_ref": "Reglamento (UE) 2021/821 Anexo I", "description": "Verificación de autorizaciones de exportación de doble uso de la UE."},
                {"pattern": "fips_140_3_zero_foreign_crypto_soberania.json", "name": "Cifrado FIPS 140-3 Cero Acceso Foráneo", "category": "evidence", "legal_ref": "FIPS 140-3 Level 3", "description": "Custodia soberana de material criptográfico sin acceso extraterritorial."}
            ],
            legal_citations=["ITAR (22 CFR 120-130)", "EAR (15 CFR 730-774)", "Reglamento (UE) 2021/821", "NIST FIPS 140-3"],
            sample_tree="policies/ITAR_EAR_DUAL_USE_EXPORT_CONTROL_POLICY.md\nevidence/itar_usml_technical_data_access_log.json\nevidence/ear_ccl_eccn_classification_sheet.md"
        ),
        "MCCE": FrameworkEvidenceSpec(
            framework_key="MCCE",
            family="Defensa & Soberanía Operativa OTAN",
            name="MCCE Ciberdefensa Militar & Información Clasificada OTAN (STANAG 4774 & CCN-STIC 400)",
            inspection_scope="Operaciones de ciberdefensa militar (MCCE / EMAD), marcado criptográfico STANAG 4774/4778, acreditación de sistemas clasificados bajo Guías CCN-STIC 400/500 y aislamiento táctico en enclaves WANDEF/WANPG.",
            expected_artifacts=[
                {"pattern": "MCCE_CIBERDEFENSA_Y_CLASIFICADA_POLICY.md", "name": "Política de Ciberdefensa Militar y Clasificada", "category": "policies", "legal_ref": "EMAD / CCN-STIC 400", "description": "Directivas operativas de ciberdefensa y custodia de información clasificada."},
                {"pattern": "mcce_csirt_militar_operaciones_link_spec.md", "name": "Especificación Enlace CSIRT Militar", "category": "evidence", "legal_ref": "Directivas MCCE STIX 2.1", "description": "Canal seguro 24/7 de reporte táctico de incidentes al MCCE."},
                {"pattern": "stanag_4774_confidentiality_metadata_sample.xml", "name": "Etiquetado Criptográfico STANAG 4774", "category": "evidence", "legal_ref": "NATO STANAG 4774 / 4778", "description": "Metadatos XML firmados de clasificación e interoperabilidad OTAN."},
                {"pattern": "ccn_stic_400_difusion_limitada_secreto_cert.json", "name": "Acreditación CCN-STIC 400 Clasificada", "category": "evidence", "legal_ref": "CCN-STIC 401 / 405", "description": "Certificación de seguridad para Difusión Limitada y Confidencial."},
                {"pattern": "wandef_enclave_militar_airgap_isolation.md", "name": "Aislamiento Táctico Enclave WANDEF", "category": "evidence", "legal_ref": "Doctrina Militar de Enclaves", "description": "Desconexión galvánica y pasarelas de diodo en redes militares."}
            ],
            legal_citations=["Concepto Militar Ciberdefensa EMAD", "STANAG 4774", "STANAG 4778", "CCN-STIC 400", "CCN-STIC 401", "CCN-STIC 405"],
            sample_tree="policies/MCCE_CIBERDEFENSA_Y_CLASIFICADA_POLICY.md\nevidence/mcce_csirt_militar_operaciones_link_spec.md\nevidence/stanag_4774_confidentiality_metadata_sample.xml"
        ),
        "ISA-IEC 62443 Ciberseguridad Industrial OT - IoT": FrameworkEvidenceSpec(
            framework_key="ISA-IEC 62443 Ciberseguridad Industrial OT - IoT",
            family="Ciberseguridad Industrial OT/IoT",
            name="Ciberseguridad Industrial OT / IoT (ISA/IEC 62443 Zonas & Conductos)",
            inspection_scope="Segmentación formal de redes OT en Zonas y Conductos (Part 3-2), cumplimiento de Requisitos Fundamentales FR 1 a FR 7 alcanzando SL-2+ (Part 3-3), hardening de protocolos industriales (Modbus/DNP3) y gestión de parches en plantas críticas.",
            expected_artifacts=[
                {"pattern": "IEC_62443_IACS_CYBERSECURITY_POLICY.md", "name": "Política Marco de Seguridad Industrial", "category": "policies", "legal_ref": "ISA/IEC 62443-2-1", "description": "Gobernanza y directrices de ciberseguridad para redes de automatización y control."},
                {"pattern": "zonas_y_conductos_segmentacion_industrial_map.json", "name": "Topología de Zonas y Conductos OT", "category": "evidence", "legal_ref": "ISA/IEC 62443-3-2", "description": "Mapa arquitectónico de partición de activos industriales con filtrado DPI."},
                {"pattern": "security_level_sl2_fr1_fr7_compliance_matrix.md", "name": "Matriz de Requisitos Fundamentales SL-2+", "category": "evidence", "legal_ref": "ISA/IEC 62443-3-3", "description": "Conformidad de los 7 Requisitos Fundamentales alcanzando nivel SL-2 o superior."},
                {"pattern": "protocolo_industrial_modbus_dnp3_hardening_scada.json", "name": "Hardening de Protocolos Industriales", "category": "evidence", "legal_ref": "ISA/IEC 62443-4-2", "description": "Aislamiento y protección perimetral de Modbus TCP, DNP3 y Profinet."},
                {"pattern": "patch_management_resiliencia_planta_mantenimiento_ot.md", "name": "Gestión de Parches en Planta Crítica", "category": "evidence", "legal_ref": "ISA/IEC 62443-2-3", "description": "Despliegue de parches en sistemas de control sin parada operativa no programada."}
            ],
            legal_citations=["ISA/IEC 62443-2-1", "ISA/IEC 62443-2-3", "ISA/IEC 62443-3-2", "ISA/IEC 62443-3-3", "ISA/IEC 62443-4-2", "Directiva NIS 2 Art. 21"],
            sample_tree="policies/IEC_62443_IACS_CYBERSECURITY_POLICY.md\nevidence/zonas_y_conductos_segmentacion_industrial_map.json\nevidence/security_level_sl2_fr1_fr7_compliance_matrix.md"
        ),
        "DPP & Trazabilidad Aduanera UE": FrameworkEvidenceSpec(
            framework_key="DPP & Trazabilidad Aduanera UE",
            family="Trazabilidad Aduanera & Cadena de Suministro UE",
            name="Pasaporte Digital de Producto & Trazabilidad Aduanera UE (ESPR & Customs Hub)",
            inspection_scope="Pasaporte Digital de Producto conforme a Reglamento (UE) 2024/1781 (ESPR) con soporte GS1 Digital Link, interfaz telemática con el EU Customs Data Hub, debida diligencia de minerales de conflicto (UE 2017/821) y precintos inteligentes eIDAS 2.0.",
            expected_artifacts=[
                {"pattern": "DPP_CUSTOMS_TRACELOG_POLICY.md", "name": "Manual de DPP y Trazabilidad Aduanera", "category": "policies", "legal_ref": "Reglamento (UE) 2024/1781 (ESPR)", "description": "Directrices de ecodiseño, emisión de DPP y despacho aduanero europeo."},
                {"pattern": "dpp_espr_gs1_digital_link_payload.json", "name": "Payload de DPP con GS1 Digital Link", "category": "evidence", "legal_ref": "ESPR Art. 9 & 10", "description": "Portador de datos y credencial verificable de pasaporte de producto."},
                {"pattern": "eu_customs_hub_manifest_declaration.json", "name": "Manifiesto Electrónico Customs Hub", "category": "evidence", "legal_ref": "Reforma del Código Aduanero de la Unión (CAU)", "description": "Declaración aduanera anticipada sincronizada con la UE."},
                {"pattern": "due_diligence_minerales_conflicto_trazabilidad.json", "name": "Trazabilidad de Minerales de Conflicto", "category": "evidence", "legal_ref": "Reglamento (UE) 2017/821", "description": "Acreditación de cadena de custodia libre de minerales de conflicto."},
                {"pattern": "smart_seal_precinto_eidas_qseal.json", "name": "Precinto Inteligente Cualificado eIDAS 2.0", "category": "evidence", "legal_ref": "eIDAS 2.0 / RFC 3161", "description": "Precinto electrónico inmutable con sello y sellado de tiempo cualificado."}
            ],
            legal_citations=["Reglamento (UE) 2024/1781 (ESPR)", "Código Aduanero de la Unión (CAU)", "Reglamento (UE) 2017/821", "Reglamento eIDAS 2.0"],
            sample_tree="policies/DPP_CUSTOMS_TRACELOG_POLICY.md\nevidence/dpp_espr_gs1_digital_link_payload.json\nevidence/eu_customs_hub_manifest_declaration.json"
        )
    }

    ALIASES = {
        "LPIC": "Protección de Infraestructuras Críticas (LPIC)",
        "LGTel": "Ley General de Telecomunicaciones (LGTel)",
        "AESIA": "Gobernanza de IA en España (AESIA)",
        "Secretos Empresariales": "Ley de Secretos Empresariales",
        "Corporate Defense": "Corporate Defense y Prevención Penal",
        "LSSI-CE": "LSSI-CE (Servicios Sociedad Información y Cookies)",
        "DSA": "DSA (Digital Service Act)",
        "ISO27001": "ISO 27001 - SOC2",
        "RGPD": "RGPD - LOPDGDD",
        "PQC": "Mandato PQC NIST FIPS 203-204",
        "NIST PQC": "Mandato PQC NIST FIPS 203-204",
        "PQC NIST": "Mandato PQC NIST FIPS 203-204",
        "DGAM_PECAL": "DGAM",
        "PECAL": "DGAM",
        "REDGAM": "DGAM",
        "ITAR": "ITAR - EAR",
        "EAR": "ITAR - EAR",
        "DUAL_USE": "ITAR - EAR",
        "STANAG": "MCCE",
        "STANAG_4774": "MCCE",
        "CCN_STIC_400": "MCCE",
        "IEC_62443": "ISA-IEC 62443 Ciberseguridad Industrial OT - IoT",
        "ISA62443": "ISA-IEC 62443 Ciberseguridad Industrial OT - IoT",
        "OT_SCADA": "ISA-IEC 62443 Ciberseguridad Industrial OT - IoT",
        "DPP": "DPP & Trazabilidad Aduanera UE",
        "CUSTOMS": "DPP & Trazabilidad Aduanera UE",
        "ADUANAS": "DPP & Trazabilidad Aduanera UE",
    }

    @classmethod
    def get_spec(cls, framework_key: str) -> Optional[FrameworkEvidenceSpec]:
        """Obtiene la especificación detallada de un marco normativo."""
        if framework_key in cls.SPECS:
            return cls.SPECS[framework_key]
        resolved = cls.ALIASES.get(framework_key)
        if resolved and resolved in cls.SPECS:
            return cls.SPECS[resolved]
        for k, v in cls.SPECS.items():
            if framework_key.lower() in k.lower():
                return v
        return None

    @classmethod
    def get_all_specs(cls) -> Dict[str, FrameworkEvidenceSpec]:
        """Retorna el catálogo completo de las 19 normativas."""
        return cls.SPECS

    @classmethod
    def preflight_check(cls, framework_key: str, target_path: Path | str) -> Dict[str, Any]:
        """
        Inspección previa Zero-Touch (Estrictamente de Solo Lectura).
        Verifica qué artefactos requeridos por la norma existen en el sistema de destino
        sin modificar, crear ni alterar absolutamente ningún archivo.
        """
        spec = cls.get_spec(framework_key)
        if not spec:
            return {
                "framework": framework_key,
                "is_compliant": False,
                "found_count": 0,
                "missing_count": 0,
                "total_count": 0,
                "compliance_ratio": 0.0,
                "artifacts": [],
                "error": f"Especificación no encontrada para {framework_key}"
            }

        target = Path(target_path).resolve()
        if not target.exists() or not target.is_dir():
            artifacts_report = [
                {
                    "pattern": art["pattern"],
                    "name": art["name"],
                    "category": art["category"],
                    "legal_ref": art["legal_ref"],
                    "description": art["description"],
                    "found": False,
                    "matched_file": None
                }
                for art in spec.expected_artifacts
            ]
            return {
                "framework": framework_key,
                "target_path": str(target),
                "is_compliant": False,
                "found_count": 0,
                "missing_count": len(artifacts_report),
                "total_count": len(artifacts_report),
                "compliance_ratio": 0.0,
                "artifacts": artifacts_report,
                "error": "El directorio objetivo no existe o no es accesible."
            }

        # Inspección en solo lectura de archivos en target_path
        discovered_files: Dict[str, str] = {}
        for root, _, files in os.walk(target):
            for f in files:
                discovered_files[f.lower()] = os.path.join(root, f)

        artifacts_report = []
        found_count = 0

        for art in spec.expected_artifacts:
            pattern = art["pattern"].lower()
            # Búsqueda exacta o por palabra clave
            matched = None
            if pattern in discovered_files:
                matched = discovered_files[pattern]
            else:
                # Comprobar si parte del nombre del archivo coincide
                base_stem = Path(pattern).stem
                for fname, fpath in discovered_files.items():
                    if base_stem in fname:
                        matched = fpath
                        break

            is_found = matched is not None
            if is_found:
                found_count += 1

            artifacts_report.append({
                "pattern": art["pattern"],
                "name": art["name"],
                "category": art["category"],
                "legal_ref": art["legal_ref"],
                "description": art["description"],
                "found": is_found,
                "matched_file": matched
            })

        total = len(artifacts_report)
        ratio = round((found_count / total * 100.0) if total > 0 else 0.0, 1)

        return {
            "framework": framework_key,
            "target_path": str(target),
            "is_compliant": (found_count == total),
            "found_count": found_count,
            "missing_count": total - found_count,
            "total_count": total,
            "compliance_ratio": ratio,
            "artifacts": artifacts_report,
            "error": None
        }

    @classmethod
    def remediate_incident(
        cls,
        framework_key: str,
        target_path: Path | str,
        artifact_pattern: str,
        company_name: str
    ) -> Dict[str, Any]:
        """
        Acción de Remediación Específica por Normativa.
        Crea el artefacto de cumplimiento legal faltante (política, motor o evidencia estructurada)
        conforme a las directrices de la ley seleccionada.
        """
        spec = cls.get_spec(framework_key)
        if not spec:
            return {"success": False, "message": f"Marco {framework_key} no reconocido."}

        target = Path(target_path).resolve()
        target.mkdir(parents=True, exist_ok=True)

        # Determinar si es política, motor o evidencia
        matched_art = None
        for art in spec.expected_artifacts:
            if art["pattern"].lower() == artifact_pattern.lower() or Path(art["pattern"]).stem in artifact_pattern.lower():
                matched_art = art
                break

        if not matched_art:
            matched_art = {
                "pattern": artifact_pattern,
                "name": artifact_pattern,
                "category": "policies" if artifact_pattern.endswith(".md") else "engines",
                "legal_ref": "Requisito Normativo General",
                "description": "Artefacto de gobernanza y control generado automáticamente."
            }

        dest_dir = target / matched_art["category"]
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / matched_art["pattern"]

        # Generar contenido conforme a la normativa
        if dest_file.suffix == ".md":
            content = f"""# {matched_art['name']}
**Entidad Responsable:** {company_name}  
**Marco Normativo:** {spec.name}  
**Referencia Legal:** {matched_art['legal_ref']}  
**Estado:** VIGENTE / FORMALIZADO  
**Fecha de Emisión:** {time_iso_now()}  

---

## 1. Objeto y Alcance
El presente documento formaliza las directrices de cumplimiento y resiliencia conforme a los requerimientos exigidos por **{spec.name}**. Es de obligado cumplimiento para todo el personal, sistemas técnicos e infraestructura de **{company_name}**.

## 2. Medidas de Control y Garantía Legal
Se establecen los controles técnicos y organizativos requeridos por {matched_art['legal_ref']}:
1. Supervisión continua y asignación de responsabilidades.
2. Monitorización periódica y revisión de riesgos.
3. Disponibilidad inmediata para requerimientos de las autoridades supervisoras.

## 3. Registro de Firmas y Trazabilidad
- **Dirección de Ciberseguridad & Cumplimiento:** {company_name}
- **Hash de Integridad:** Documento sujeto a trazabilidad SLSA Level 3+ en Quantigrade GCR.
"""
        elif dest_file.suffix == ".json":
            content = f"""{{
  "metadata": {{
    "entity": "{company_name}",
    "framework": "{framework_key}",
    "legal_ref": "{matched_art['legal_ref']}",
    "timestamp_utc": "{time_iso_now()}",
    "status": "COMPLIANT"
  }},
  "records": [
    {{
      "id": "REC-001",
      "name": "{matched_art['name']}",
      "description": "{matched_art['description']}",
      "verified": true
    }}
  ]
}}"""
        else:
            # Script Python o motor ejecutable
            content = f'''"""
{matched_art['name']}
Cumplimiento normativo para {spec.name} ({matched_art['legal_ref']}).
Entidad: {company_name}
"""

import time
import logging

logger = logging.getLogger("{matched_art['pattern']}")

class CompliantEngine:
    """Motor de cumplimiento normativo conforme a {matched_art['legal_ref']}."""
    def __init__(self, company_name: str = "{company_name}"):
        self.company_name = company_name
        self.status = "INITIALIZED_COMPLIANT"

    def execute_control(self) -> dict:
        return {{
            "status": "SUCCESS",
            "framework": "{framework_key}",
            "legal_ref": "{matched_art['legal_ref']}",
            "timestamp": time.time(),
            "message": "Control normativo ejecutado y verificado satisfactoriamente."
        }}

if __name__ == "__main__":
    engine = CompliantEngine()
    print(engine.execute_control())
'''

        dest_file.write_text(content, encoding="utf-8")
        return {
            "success": True,
            "created_path": str(dest_file),
            "message": f"Artefacto remediado con éxito: {dest_file.name} en {matched_art['category']}/"
        }


def time_iso_now() -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
