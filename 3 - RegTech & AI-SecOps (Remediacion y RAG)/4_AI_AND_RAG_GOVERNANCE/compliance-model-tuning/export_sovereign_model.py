"""export_sovereign_model.py — LoRA Weights Merger & Ollama Modelfile Generator.
=============================================================================
Fusiona los adaptadores LoRA entrenados con el modelo base y genera la configuración
Modelfile para su despliegue en local/soberano (Ollama / vLLM / llama.cpp).

Cumplimiento: ENS Alta (Soberanía del Dato, Inferencia On-Premise sin salida a Internet).
"""

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).parent.resolve()
MODEL_OUTPUT_DIR = CURRENT_DIR / "sovereign_model"
MODEL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


OLLAMA_MODELFILE_CONTENT = """# BunkerOS Sovereign Compliance Model 8B (ENS Alta / DORA / EU AI Act)
FROM ./sovereign-compliance-8b.Q4_K_M.gguf

# Parametros de Inferencia Determinista y Auditoria
PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER repeat_penalty 1.15
PARAMETER stop "<|eot_id|>"
PARAMETER stop "<|start_header_id|>"
PARAMETER stop "<|end_header_id|>"

# System Prompt Blindado
SYSTEM \"\"\"
Eres el Asistente Soberano de Auditoría Técnica y Cumplimiento Normativo de BunkerOS.
Tu conocimiento está especializado en:
1. Reglamento Europeo de Inteligencia Artificial (EU AI Act - Reglamento UE 2024/1689).
2. Reglamento de Resiliencia Operativa Digital (DORA - Reglamento UE 2022/2554).
3. Esquema Nacional de Seguridad (ENS - RD 311/2022, Categoría Alta).
4. Directiva de Seguridad de las Redes y Sistemas de Información (NIS2 - Directiva UE 2022/2555).
5. Reglamento General de Protección de Datos (RGPD - Reglamento UE 2016/679).

Reglas de Comportamiento:
- Respuestas precisas, estructuradas y con citas normativas formales.
- Si una afirmación no está fundamentada en la normativa oficial, declara explícitamente la ausencia de regulación aplicable.
- Formato de salida estructurado en Markdown con encabezados ejecutivos.
\"\"\"
"""


def generate_ollama_modelfile(output_dir: Path = MODEL_OUTPUT_DIR):
    modelfile_path = output_dir / "Modelfile"
    with open(modelfile_path, "w", encoding="utf-8") as f:
        f.write(OLLAMA_MODELFILE_CONTENT)
    return modelfile_path


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    modelfile = generate_ollama_modelfile()
