# Orquestador de Auditoría Normativa de 3 Niveles

Este proyecto consolida los scripts y herramientas de evaluación de múltiples normativas de ciberseguridad en una **arquitectura de 3 niveles de exigencia acumulativa**, proporcionando un único orquestador (`orchestrator.py`) para ejecutar auditorías completas.

## Arquitectura de 3 Niveles

1. **Nivel 1: Gobernanza (Requisitos Estratégicos y Legales)**
   - Enfocado en cumplimiento organizativo, protección de datos y marcos base.
   - *Normativas:* RGPD, LOPDGDD, ENS (Marco Organizativo), EU Cyber Act/ENISA.
2. **Nivel 2: Operativo (Arquitectura, Apps y Cadena de Suministro)**
   - Enfocado en resiliencia de software, seguridad de aplicaciones y cadena de suministro.
   - *Normativas:* NIS2, NIST SP 800-53/161, OWASP Top 10, OWASP LLM, EU AI Act, Supply Chain Security.
3. **Nivel 3: Exigencia Técnica (Máxima Exigencia y Criptografía)**
   - Enfocado en resiliencia técnica extrema, criptografía post-cuántica y hardening a bajo nivel.
   - *Normativas:* DORA, FIPS 140-3, FIPS 186-5/197-202, PQC FIPS, IP/PE Hardening.

---

## 1. Inicialización (Requisito Previo)

Antes de ejecutar el orquestador por primera vez, debes migrar y clasificar los scripts originales en sus respectivos niveles. Ejecuta:

```bash
python init_audit_structure.py
```

Esto creará automáticamente las carpetas `Nivel_1_Gobernanza`, `Nivel_2_Operativo` y `Nivel_3_Exigencia_Tecnica` en la raíz del proyecto, y copiará recursivamente los directorios normativos.

---

## 2. Uso del Orquestador

El script `orchestrator.py` es la herramienta principal para disparar auditorías. Mapea dinámicamente los scripts ejecutables en los niveles seleccionados y consolida los resultados.

### Opciones de CLI:

- `--level [1|2|3]`: Ejecución explícita por nivel. Es **acumulativo** (el Nivel 3 ejecutará también el 1 y el 2).
- `--sector [pyme|saas|financiero|critico]`: Selecciona automáticamente el nivel basándose en el sector:
  - `pyme` -> Nivel 1
  - `saas` -> Nivel 2
  - `financiero`, `critico` -> Nivel 3
- `--target <ruta>`: La ruta de la infraestructura, código fuente o proyecto a auditar.
- `--output <ruta>`: (Opcional) Ruta donde se guardarán los informes generados. Por defecto: `./reports/`

### Ejemplos de uso:

**1. Evaluación para entorno Financiero:**
```bash
python orchestrator.py --sector financiero --target "C:/mi_app_bancaria"
```

**2. Evaluación estricta de Nivel 2 con ruta de reporte personalizada:**
```bash
python orchestrator.py --level 2 --target "/opt/saas/backend" --output "./auditoria_mensual"
```

**3. Modo Interactivo:**
Si lo ejecutas sin argumentos, te pedirá por consola la información necesaria:
```bash
python orchestrator.py
```

---

## 3. Informes Generados

Tras finalizar, el orquestador creará una carpeta `./reports/` (o la que se especifique) y generará dos archivos:
- **`audit_report_YYYYMMDD_LX.json`**: Informe técnico legible por máquinas para integraciones CI/CD o métricas.
- **`audit_report_YYYYMMDD_LX.md`**: Informe ejecutivo en Markdown con resumen de cumplimiento global, hallazgos críticos detectados en el `stderr` de cada herramienta y plan de remediación.
