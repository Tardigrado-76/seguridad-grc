#!/usr/bin/env bash
# ==============================================================================
# export_gguf.sh — Script de Conversión a GGUF y Despliegue en Ollama
# ==============================================================================
set -e

BASE_MODEL="meta-llama/Meta-Llama-3-8B-Instruct"
CHECKPOINT_DIR="./checkpoints/sovereign-compliance-8b-lora"
MERGED_DIR="./merged_model"
OUTPUT_GGUF="./sovereign_model/sovereign-compliance-8b.Q4_K_M.gguf"

echo "====================================================================="
echo "🔄 1. Fusionando adaptadores LoRA con el Modelo Base..."
echo "====================================================================="
python -c "
import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

base_model = AutoModelForCausalLM.from_pretrained(
    '${BASE_MODEL}',
    torch_dtype=torch.float16,
    device_map='cpu'
)
model = PeftModel.from_pretrained(base_model, '${CHECKPOINT_DIR}')
merged = model.merge_and_unload()
merged.save_pretrained('${MERGED_DIR}')

tokenizer = AutoTokenizer.from_pretrained('${BASE_MODEL}')
tokenizer.save_pretrained('${MERGED_DIR}')
print('✅ Fusión completada en ${MERGED_DIR}')
"

echo "====================================================================="
echo "📦 2. Convirtiendo a GGUF y aplicando Cuantización 4-bit (Q4_K_M)..."
echo "====================================================================="
if [ -d "../llama.cpp" ]; then
    python ../llama.cpp/convert_hf_to_gguf.py "${MERGED_DIR}" --outfile "${OUTPUT_GGUF}" --outtype q4_k_m
    echo "✅ Archivo GGUF creado en ${OUTPUT_GGUF}"
else
    echo "⚠️ llama.cpp no encontrado en ../llama.cpp. Se asume compilación vía Ollama/Unsloth."
fi

echo "====================================================================="
echo "🦙 3. Generando Modelfile y registrando en Ollama local..."
echo "====================================================================="
python export_sovereign_model.py

if command -v ollama &> /dev/null; then
    cd sovereign_model
    ollama create sovereign-compliance-8b -f Modelfile
    echo "🚀 Modelo 'sovereign-compliance-8b' listo y desplegado en Ollama local."
else
    echo "ℹ️ Ollama CLI no disponible en el PATH del sistema host."
fi
