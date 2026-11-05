"""
Module: populate_grc_and_interviews.py
Description: Production-ready enterprise component for Populate Grc And Interviews.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


logger = logging.getLogger(__name__)
"""
Module: populate_grc_and_interviews.py
Description: Production-ready enterprise component for Populate Grc And Interviews.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import json
from pathlib import Path

base_dir = Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/NORMATIVAS/AUDITORIAS_FINAL")

# 1. GRC Templates Content
TEMPLATES = {
    "PLANTILLA_Politica_Seguridad_Informacion.md": """# POLÍTICA GENERAL DE SEGURIDAD DE LA INFORMACIÓN
**Normativa:** ENS / ISO 27001
**Aprobado por:** Dirección General / CISO

## 1. OBJETIVO Y ALCANCE
La presente política establece las directrices para proteger la confidencialidad, integridad, disponibilidad y autenticidad de los activos de información de la organización.

## 2. PRINCIPIOS RECTORES
- Mínimo Privilegio y Necesidad de Conocer.
- Gestión de Riesgos Continuada.
- Cumplimiento de la Legalidad Vigente.

---
*Firmado electrónicamente por la Dirección.*
""",
    "PLANTILLA_Inventario_Activos.csv": """ID_Activo,Nombre_Activo,Tipo,Propietario,Ubicacion,Criticidad_CID
ACT-001,Servidor Base de Datos,Hardware,Dpto TI,CPD Principal,ALTA
ACT-002,Código Fuente App,Software,Equipo Dev,GitHub Enterprise,ALTA
ACT-003,Datos de Clientes,Informacion,Dpto Legal,Cloud DB,ALTA
""",
    "PLANTILLA_Uso_Aceptable.md": """# POLÍTICA DE USO ACEPTABLE DE RECURSOS DE TI
**Destinatarios:** Todo el personal de la empresa.

1. Queda prohibida la instalación de software no autorizado.
2. El uso de contraseñas debe seguir la política corporativa (mínimo 14 caracteres + MFA).
3. No se permite el almacenamiento de información confidencial en dispositivos personales no gestionados.
""",
    "PLANTILLA_Plan_Respuesta_Incidentes.md": """# PLAN DE RESPUESTA Y GESTIÓN DE INCIDENTES
**Objetivo:** Minimizar el impacto operativo ante un incidente de ciberseguridad.

## ROLES DE CONTACTO DE EMERGENCIA
- **CISO / Responsables de Seguridad:** +34 600 000 000
- **Equipo Técnico TI:** +34 600 000 001
- **Asesoría Jurídica / DPO:** +34 600 000 002

## FASES DE ACTUACIÓN
1. Detección y Análisis
2. Contención Inmediata (Aislamiento de red)
3. Erradicación y Recuperación
4. Notificación a Autoridades (CCN-CERT / INCIBE / AEPD)
""",
    "PLANTILLA_Plan_Continuidad_Negocio_BCP.md": """# PLAN DE CONTINUIDAD DE NEGOCIO (BCP)
**Objetivo:** Garantizar la operativa de servicios críticos ante desastres severos.

- **RTO (Recovery Time Objective):** < 4 horas.
- **RPO (Recovery Point Objective):** < 1 hora.
- **Ubicación Secundaria:** Cloud Failover Region West.
""",
    "PLANTILLA_Acuerdos_SLAs_Proveedores.md": """# ANEXO DE CIBERSEGURIDAD Y SLAs PARA PROVEEDORES (NIS2 / ENS)
1. El proveedor garantiza un tiempo de disponibilidad del 99.9%.
2. Notificación obligatoria de brechas de seguridad al contratante en < 12 horas.
3. Derecho a auditar anualmente las medidas de seguridad del proveedor.
""",
    "PLANTILLA_Plan_Recuperacion_Desastres_DRP.md": """# PLAN DE RECUPERACIÓN ANTE DESASTRES (DRP)
**Procedimiento de Restauración Bare-Metal & Backup Inmutable:**
1. Despliegue de imágenes base verificadas.
2. Desbloqueo del Bunker de Backups (Air-gapped).
3. Verificación de firmas criptográficas SHA-256 pre-arranque.
""",
    "PLANTILLA_Procedimiento_Evidencias_Forenses.md": """# PROCEDIMIENTO DE CADENA DE CUSTODIA FORENSE
1. Preservación de memoria RAM y logs inmutables.
2. Generación de Hashes SHA-256 en el momento de la incautación.
3. Registro de firmantes y custodios del dispositivo afectado.
""",
    "PLANTILLA_Clasificacion_Informacion.md": """# POLÍTICA DE CLASIFICACIÓN Y MANEJO DE LA INFORMACIÓN
- **PÚBLICA:** Difusión sin restricciones.
- **INTERNA:** Solo personal corporativo.
- **CONFIDENCIAL:** Acceso restringido bajo NDA explícito.
- **SECRETA / CRÍTICA:** Cifrado FIPS obligatorio en reposo y tránsito.
""",
    "PLANTILLA_Protocolo_Notificacion_24h.md": """# PROTOCOLO DE NOTIFICACIÓN TEMPRANA INCIDENTES NIS2 (24 HORAS)
1. **Notificación Temprana (24h):** Alerta inicial al CSIRT nacional (CCN-CERT/INCIBE).
2. **Notificación del Incidente (72h):** Evaluación inicial de severidad e impacto.
3. **Informe Final (1 mes):** Análisis de causa raíz y medidas correctoras.
""",
    "PLANTILLA_Manual_Higiene_Cibernetica.md": """# GUÍA DE HIGIENE CIBERNÉTICA PARA EMPLEADOS (NIS2)
- Verificación obligatoria de remitentes en correos recibidos.
- Uso de autenticación multifactor (MFA) FIDO2 / Authenticator.
- Bloqueo automático de estación de trabajo tras 3 minutos de inactividad.
""",
    "PLANTILLA_Riesgos_Cadena_Suministro.md": """# POLÍTICA DE SEGURIDAD EN LA CADENA DE SUMINISTRO (NIS2 ART. 21)
- Inventariado automático de dependencias de software (SBOM CycloneDX).
- Evaluación continuada de vulnerabilidades en librerías de terceros (CISA KEV).
""",
    "PLANTILLA_Acta_Formacion_CISO_Direccion.md": """# ACTA DE FORMACIÓN EN CIBERSEGURIDAD PARA LA ALTA DIRECCIÓN (NIS2 ART. 20)
**Fecha:** ___________
**Asistentes:** Miembros del Consejo de Administración y CEO.
**Materias:** Responsabilidad jurídica, gestión de crisis y evaluación de riesgos cibernéticos.
""",
    "PLANTILLA_Comite_Crisis_Cibernetica.md": """# CONSTITUCIÓN DEL COMITÉ DE GESTIÓN DE CRISIS CIBERNÉTICA
- **Presidente del Comité:** CEO / Director General.
- **Coordinador Técnico:** CISO.
- **Portavoz Oficial:** Director de Comunicación.
""",
    "PLANTILLA_Politica_Zero_Trust.md": """# POLÍTICA ORGANIZATIVA ZERO TRUST (NIST SP 800-207)
- Nunca confiar, siempre verificar.
- Micro-segmentación de red y autenticación continuada orientada al contexto.
"""
}

# 2. Generator function for Python Interview Scripts
def generate_interview_script(folder_name, level_code):
    return f"""# -*- coding: utf-8 -*-
import sys
import json
from pathlib import Path

def run_interview():
    logger.info(f"==================================================")
    logger.info(f" QUANTIGRADE GRC INTERVIEW - {folder_name}")
    logger.info(f" Auditoría Humana y Evaluacion Organizativa")
    logger.info(f"==================================================\\n")
    
    questions = [
        ("¿Dispone la organización de una Política de Seguridad aprobada por la Dirección?", "pol_base"),
        ("¿Se realizan controles de acceso físico restringido a las instalaciones críticas?", "acc_fisico"),
        ("¿Existe un procedimiento de concienciación y formación en ciberseguridad para empleados?", "formacion"),
        ("¿Se cuenta con un protocolo formalizado para la gestión de incidentes?", "incidentes")
    ]
    
    results = []
    for q, code in questions:
        ans = input(f"[?] {{q}} (s/n): ").strip().lower()
        status = "PASS" if ans == 's' else "FAIL"
        results.append({{
            "domain": "Entrevista Humana GRC",
            "control": code,
            "status": status,
            "detail": "Verificado mediante entrevista con dirección." if status == "PASS" else "Falta evidencia u homologación."
        }})
        
    logger.info(f"\\n[+] Entrevista GRC finalizada para {folder_name}.")
    
    # Save output to be read by reporter
    out_file = Path(__file__).parent / "grc_interview_results.json"
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)
        
    return results

if __name__ == "__main__":
    run_interview()
"""

# Map files to directories
DIR_MAPPING = {
    "ENS 1": [
        "PLANTILLA_Politica_Seguridad_Informacion.md",
        "PLANTILLA_Inventario_Activos.csv",
        "PLANTILLA_Uso_Aceptable.md"
    ],
    "ENS 2": [
        "PLANTILLA_Politica_Seguridad_Informacion.md",
        "PLANTILLA_Inventario_Activos.csv",
        "PLANTILLA_Uso_Aceptable.md",
        "PLANTILLA_Plan_Respuesta_Incidentes.md",
        "PLANTILLA_Plan_Continuidad_Negocio_BCP.md",
        "PLANTILLA_Acuerdos_SLAs_Proveedores.md"
    ],
    "ENS 3": [
        "PLANTILLA_Politica_Seguridad_Informacion.md",
        "PLANTILLA_Inventario_Activos.csv",
        "PLANTILLA_Uso_Aceptable.md",
        "PLANTILLA_Plan_Respuesta_Incidentes.md",
        "PLANTILLA_Plan_Continuidad_Negocio_BCP.md",
        "PLANTILLA_Acuerdos_SLAs_Proveedores.md",
        "PLANTILLA_Plan_Recuperacion_Desastres_DRP.md",
        "PLANTILLA_Procedimiento_Evidencias_Forenses.md",
        "PLANTILLA_Clasificacion_Informacion.md"
    ],
    "NIS2 bajo": [
        "PLANTILLA_Protocolo_Notificacion_24h.md",
        "PLANTILLA_Manual_Higiene_Cibernetica.md"
    ],
    "NIS2 medio": [
        "PLANTILLA_Protocolo_Notificacion_24h.md",
        "PLANTILLA_Manual_Higiene_Cibernetica.md",
        "PLANTILLA_Riesgos_Cadena_Suministro.md",
        "PLANTILLA_Acta_Formacion_CISO_Direccion.md"
    ],
    "NIS2 alto": [
        "PLANTILLA_Protocolo_Notificacion_24h.md",
        "PLANTILLA_Manual_Higiene_Cibernetica.md",
        "PLANTILLA_Riesgos_Cadena_Suministro.md",
        "PLANTILLA_Acta_Formacion_CISO_Direccion.md",
        "PLANTILLA_Comite_Crisis_Cibernetica.md",
        "PLANTILLA_Politica_Zero_Trust.md"
    ]
}

def main():
    logger.info("[*] Poblando directorios de AUDITORIAS_FINAL con plantillas GRC y scripts de entrevista...")
    
    for folder, templates_list in DIR_MAPPING.items():
        folder_path = base_dir / folder
        folder_path.mkdir(exist_ok=True)
        
        # Write Templates
        for tmpl_name in templates_list:
            tmpl_file = folder_path / tmpl_name
            with open(tmpl_file, 'w', encoding='utf-8') as f:
                f.write(TEMPLATES[tmpl_name])
            logger.info(f"  [{folder}] Plantilla añadida: {tmpl_name}")
            
        # Write Interview script
        script_name = f"grc_interview_{folder.replace(' ', '_').lower()}.py"
        script_file = folder_path / script_name
        with open(script_file, 'w', encoding='utf-8') as f:
            f.write(generate_interview_script(folder, folder.lower()))
        logger.info(f"  [{folder}] Script de entrevista añadido: {script_name}")

    logger.info("\n[+] Poblamiento GRC completado exitosamente.")

if __name__ == "__main__":
    main()
