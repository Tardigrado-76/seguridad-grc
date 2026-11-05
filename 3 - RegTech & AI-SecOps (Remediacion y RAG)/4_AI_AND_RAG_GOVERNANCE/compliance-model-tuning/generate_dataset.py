"""generate_dataset.py — Compliance Supervised Fine-Tuning (SFT) Dataset Generator.
================================================================================
Generador y sintetizador de datos de entrenamiento para Fine-Tuning de Modelos Soberanos.
Convierte directivas regulatorias (EU AI Act, DORA, ENS Alta, NIS2, RGPD) en pares
de instrucción/respuesta estructurados en formatos Alpaca y ChatML.

Cumplimiento: EU AI Act Art. 10 (Gobernanza y Calidad de Datos de Entrenamiento)
"""

import json
import random
import sys
from pathlib import Path
from typing import Any

CURRENT_DIR = Path(__file__).parent.resolve()
OUTPUT_DIR = CURRENT_DIR / "dataset"

# ---------------------------------------------------------------------------
# PLANTILLAS DE CONOCIMIENTO REGULATORIO EXPERTO
# ---------------------------------------------------------------------------
RAW_COMPLIANCE_KNOWLEDGE: list[dict[str, Any]] = [
    {
        "framework": "EU AI Act",
        "domain": "Clasificación de Riesgo",
        "instruction": "Clasifica un sistema de IA utilizado para la selección y contratación de personal según la EU AI Act.",
        "input": "Sistema automatizado de filtrado de CVs y puntuación de candidatos mediante análisis de vídeo y texto.",
        "output": (
            "### Clasificación según EU AI Act (Reglamento UE 2024/1689):\n"
            "- **Nivel de Riesgo:** ALTO RIESGO (Anexo III, Sección 4: 'Empleo, gestión de trabajadores y acceso al autoempleo').\n"
            "- **Obligaciones Principales:**\n"
            "  1. Sistema de gestión de riesgos continuo (Art. 9).\n"
            "  2. Gobernanza de datos para mitigar sesgos discriminatorios (Art. 10).\n"
            "  3. Documentación técnica y registro de eventos automático (Art. 11 y 12).\n"
            "  4. Supervisión humana efectiva (Art. 14).\n"
            "  5. Ciberseguridad y robustez técnica (Art. 15).\n"
            "- **Sanciones por Incumplimiento:** Multas de hasta 35 millones de euros o el 7% del volumen de negocio global."
        ),
    },
    {
        "framework": "DORA",
        "domain": "Pruebas de Resiliencia Operativa Digital",
        "instruction": "¿Cuáles son los requisitos para la realización de pruebas avanzadas de penetración guiadas por amenazas (TLAP) bajo DORA?",
        "input": "Entidad bancaria sujeta a DORA en categoría significativa.",
        "output": (
            "### Requisitos TLAP bajo DORA (Reglamento UE 2022/2554, Art. 26-27):\n"
            "- **Periodicidad:** Al menos cada 3 años para entidades financieras designadas por las autoridades.\n"
            "- **Alcance:** Debe cubrir funciones críticas o importantes y abarcar a proveedores terceros de servicios TIC.\n"
            "- **Requisitos de Probadores (Testers):**\n"
            "  1. Máxima idoneidad profesional y certificaciones acreditadas (CREST, TIBER-EU).\n"
            "  2. Seguro de indemnización profesional para riesgos de ciberseguridad.\n"
            "  3. Los probadores internos solo se permiten bajo validación de la autoridad y con probadores externos liderando.\n"
            "- **Notificación:** Entrega de certificado de realización y plan de remediación a la Autoridad Competente."
        ),
    },
    {
        "framework": "ENS Alta",
        "domain": "Custodia y Trazabilidad de Auditoría",
        "instruction": "Describe las medidas de bastionado exigidas por el ENS en categoría Alta para el registro de actividad (op.mon.1).",
        "input": "Servidores de base de datos y microservicios que procesan información clasificada Alta.",
        "output": (
            "### Medidas de Registro de Actividad ENS Categoría Alta (Medida op.mon.1 - RD 311/2022):\n"
            "- **Inmutabilidad y Firma:** Los registros deben transferirse en tiempo real a un servidor de registros independiente y protegido contra borrado o alteración mediante firma electrónica cualificada o algoritmos criptográficos acreditados (CCN-STIC).\n"
            "- **Sincronización Horaria (op.mon.2):** Sincronización mediante NTP seguro con el Real Instituto y Observatorio de la Armada (ROA) con precisión milimétrica.\n"
            "- **Periodo de Retención:** Conservación de trazas durante un periodo mínimo de 2 años.\n"
            "- **Segregación:** Acceso restringido exclusivamente a auditores de seguridad, prohibiendo el acceso de modificación incluso a administradores de sistemas."
        ),
    },
    {
        "framework": "NIS2",
        "domain": "Gestión de Vulnerabilidades y Cadena de Suministro",
        "instruction": "¿Qué obligaciones específicas impone NIS2 respecto a la seguridad en la cadena de suministro (Supply Chain)?",
        "input": "Entidad esencial del sector energético integrando software de terceros.",
        "output": (
            "### Obligaciones de Cadena de Suministro NIS2 (Directiva UE 2022/2555, Art. 21.2.d):\n"
            "- **Evaluación de Proveedores:** Evaluación obligatoria de las vulnerabilidades específicas de cada proveedor directo y la calidad de sus prácticas de ciberseguridad.\n"
            "- **Software Bill of Materials (SBOM):** Exigencia de SBOM y trazabilidad de dependencias de código abierto (SLSA L3+).\n"
            "- **Contratos y SLAs:** Cláusulas vinculantes que garanticen divulgación coordinada de vulnerabilidades y tiempos de respuesta garantizados.\n"
            "- **Responsabilidad Directiva (Art. 20):** Los consejeros y directores son personalmente responsables del incumplimiento de estas evaluaciones."
        ),
    },
    {
        "framework": "RGPD / LOPDGDD",
        "domain": "Evaluación de Impacto en Protección de Datos (EIPD)",
        "instruction": "¿Cuándo es obligatorio realizar una EIPD antes de desplegar un modelo de Inteligencia Artificial?",
        "input": "Implementación de un sistema de recomendación crediticia basado en Machine Learning.",
        "output": (
            "### Criterios de Obligatoriedad EIPD (RGPD Art. 35 y Guía AEPD):\n"
            "- **Criterios Cumplidos:**\n"
            "  1. Toma de decisiones automatizada con efectos jurídicos o significativos (Art. 22).\n"
            "  2. Tratamiento a gran escala de datos financieros o de solvencia.\n"
            "  3. Uso de tecnologías innovadoras o emergentes (Modelos de IA / Redes Neuronales).\n"
            "- **Contenido Obligatorio de la EIPD:**\n"
            "  - Descripción sistemática de operaciones y fines del tratamiento.\n"
            "  - Evaluación de necesidad y proporcionalidad.\n"
            "  - Análisis de riesgos para los derechos y libertades de los interesados.\n"
            "  - Medidas de mitigación (Enmascaramiento PII, explicabilidad del modelo y derecho a revisión humana)."
        ),
    },
]


class ComplianceDatasetGenerator:
    """Generador y aumentador de datasets para SFT de modelos soberanos."""

    def __init__(self, output_dir: Path = OUTPUT_DIR) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_augmented_samples(self, multiplier: int = 10) -> list[dict[str, Any]]:
        """Aumenta el dataset variando estilos de instrucción y reformulaciones."""
        augmented = []
        prefixes = [
            "Como auditor de ciberseguridad, ",
            "En el contexto de una auditoría técnica regulatoria, ",
            "Por favor, responde con precisión jurídica: ",
            "Actuando como CISO corporativo, evalúa lo siguiente: ",
            "Genera un informe técnico de cumplimiento: ",
        ]

        for item in RAW_COMPLIANCE_KNOWLEDGE:
            # Versión original
            augmented.append(item)

            # Generar variaciones
            for _i in range(multiplier - 1):
                prefix = random.choice(prefixes)
                var_instruction = prefix + item["instruction"]
                augmented.append({
                    "framework": item["framework"],
                    "domain": item["domain"],
                    "instruction": var_instruction,
                    "input": item["input"],
                    "output": item["output"],
                })

        random.shuffle(augmented)
        return augmented

    def export_alpaca_format(self, samples: list[dict[str, Any]], filename: str = "compliance_sft_alpaca.json"):
        """Exporta en formato estándar Alpaca: {instruction, input, output}."""
        alpaca_data = [
            {
                "instruction": s["instruction"],
                "input": s["input"],
                "output": s["output"],
            }
            for s in samples
        ]
        out_path = self.output_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(alpaca_data, f, indent=2, ensure_ascii=False)
        return out_path

    def export_chatml_format(self, samples: list[dict[str, Any]], filename: str = "compliance_sft_chatml.json"):
        """Exporta en formato ChatML estándar para Llama-3 / Mistral."""
        chatml_data = []
        system_prompt = (
            "Eres un Auditor Jefe de Ciberseguridad y Cumplimiento Normativo (EU AI Act, DORA, ENS Alta, NIS2, RGPD). "
            "Tus respuestas deben ser rigurosas, estructuradas, citar artículos específicos y mantener estricto apego legal."
        )

        for s in samples:
            user_content = s["instruction"]
            if s["input"]:
                user_content += f"\nContexto adicional: {s['input']}"

            chatml_data.append({
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                    {"role": "assistant", "content": s["output"]},
                ],
            })

        out_path = self.output_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(chatml_data, f, indent=2, ensure_ascii=False)
        return out_path

    def build_train_val_split(self, train_ratio: float = 0.85):
        """Genera particiones de entrenamiento y validación completas."""
        samples = self.generate_augmented_samples(multiplier=20)  # 100 muestras sintéticas
        split_idx = int(len(samples) * train_ratio)
        train_samples = samples[:split_idx]
        val_samples = samples[split_idx:]

        self.export_chatml_format(train_samples, "train_chatml.json")
        self.export_chatml_format(val_samples, "val_chatml.json")
        self.export_alpaca_format(train_samples, "train_alpaca.json")
        self.export_alpaca_format(val_samples, "val_alpaca.json")

        return {
            "total_samples": len(samples),
            "train_samples": len(train_samples),
            "val_samples": len(val_samples),
            "train_chatml": str(self.output_dir / "train_chatml.json"),
            "val_chatml": str(self.output_dir / "val_chatml.json"),
        }


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    generator = ComplianceDatasetGenerator()
    summary = generator.build_train_val_split()
