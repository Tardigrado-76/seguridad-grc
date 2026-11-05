# Catálogo Sistematizado de Herramientas de Auditoría y Mitigación (TOOLS/)

Este directorio centraliza las herramientas y scripts de automatización prescritos para auditar, verificar y mitigar riesgos en los diferentes niveles normativos del **Esquema Nacional de Seguridad (ENS)**, la **Directiva NIS2** y la **Cyber Resilience Act (CRA)** para la plataforma BunkerOS.

---

## Clasificación Bifásica de Herramientas

### 1. Fase de Desarrollo y Pipeline CI/CD (Auditoría Estática y Dependencias)

| Nombre de la Herramienta | Nivel Normativo | Funcionamiento Técnico | Mitigación / Solución Aportada |
| :--- | :--- | :--- | :--- |
| **Bandit** | ENS Medio/Alto<br>CRA Art. 13 | Analiza el Árbol de Sintaxis Abstracta (AST) de Python en busca de patrones vulnerables conocidos. | Identifica y erradica llamadas inseguras al sistema, uso de criptografía débil, secretos hardcodeados y bindings inseguros (CWE-259, CWE-327). |
| **Semgrep** | ENS Medio/Alto<br>CRA Art. 13 | Motor de análisis estático semántico basado en reglas personalizadas para verificar patrones de diseño seguro. | Valida la correcta implementación de middlewares de cabeceras seguras, políticas de cookies y configuraciones CORS (CWE-693, CWE-942). |
| **pip-audit** | ENS Alto<br>NIS2 Art. 21<br>CRA (Supply Chain) | Escanea las dependencias de Python contra la base de datos de vulnerabilidades PyPI (OSV) localmente. | Previene la inclusión de paquetería de terceros con vulnerabilidades conocidas y reportadas en la cadena de suministro (CWE-1395). |
| **OWASP Dependency-Check** | ENS Alto<br>CRA Art. 13 | Escanea dependencias a nivel de compilación y genera un Software Bill of Materials (SBOM) en formato CycloneDX. | Identifica CVEs públicos en bibliotecas nativas e interactúa con el catálogo de dependencias del pipeline para bloquear compilaciones inseguras. |

### 2. Fase de Operación y Auditoría de Host (Auditoría Dinámica e Infraestructura)

| Nombre de la Herramienta | Nivel Normativo | Funcionamiento Técnico | Mitigación / Solución Aportada |
| :--- | :--- | :--- | :--- |
| **CLARA (CCN-CERT)** | ENS Medio/Alto | Herramienta oficial del Centro Criptológico Nacional de España para auditar la seguridad de hosts Windows. | Evalúa la correcta aplicación de directivas de grupo locales (GPO), cifrado de almacenamiento, políticas de contraseñas y desactivación de servicios innecesarios. |
| **INÉS (CCN-CERT)** | ENS Bajo/Medio/Alto<br>NIS2 Nivel 1 | Herramienta de auditoría organizativa y técnica que evalúa el estado general de cumplimiento del ENS. | Genera reportes de conformidad ENS, mapea controles técnicos faltantes y provee una hoja de ruta para la certificación del organismo o empresa. |
| **LinPeas / WinPeas** | ENS Medio/Alto | Script automatizado de reconocimiento de host que busca vectores locales de escalada de privilegios. | Detecta permisos débiles en archivos del sistema, configuraciones del registro incorrectas y malas prácticas de almacenamiento de credenciales (CWE-269). |
| **Falco** | ENS Alto<br>NIS2 Art. 21 | Herramienta de seguridad en tiempo de ejecución (runtime) de Kubernetes/Linux que monitorea eventos del kernel. | Detecta y alerta sobre comportamientos anómalos, como la ejecución de un shell (`bash`) dentro del servidor web, o el acceso no autorizado a `certs/` (CWE-288). |
| **Tetragon** | ENS Alto (op.mon.1)<br>NIS2 Sectores Críticos | Agente de seguridad basado en eBPF que monitoriza y aplica políticas restrictivas directamente a nivel de kernel. | Realiza contención activa (bloqueo mediante SIGKILL) en tiempo real si un proceso intenta cargar bibliotecas dynamic maliciosas o alterar binarios inmutables. |

---

## Directrices de Uso en BunkerOS

1. **Pipeline de Integración Continua (Pre-commit & Github Actions)**:
   - **Gitleaks** se ejecuta como pre-commit hook (`.pre-commit-config.yaml`) para evitar leaks de llaves.
   - **Bandit** y **verify_cisa_kev.py** se ejecutan en cada PR para auditar el código fuente y las dependencias de terceros contra exploits activos (*exploited in the wild*).

2. **Auditoría Perimetral de Producción**:
   - **CLARA** debe ser lanzada mensualmente sobre el host Windows que aloja el appliance compilado para asegurar que ninguna modificación de GPO invalide el cumplimiento de la guía CCN-STIC 811.
   - El agente **BunkerXDRAgent** emula controles dinámicos a nivel local para hosts Windows sin agentes eBPF integrales, reportando al bus de eventos de forma síncrona.
