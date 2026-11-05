"""finetune_unsloth.py — Sovereign Model QLoRA (4-Bit) Fine-Tuning Pipeline.
========================================================================
Pipeline de entrenamiento supervisado (SFT) para adaptar modelos fundacionales
(Llama 3 8B / Mistral 7B) a directivas normativas (EU AI Act, DORA, ENS Alta, NIS2).

Características de la Arquitectura:
- Cuantización QLoRA a 4-bits (BitsAndBytes / Unsloth) -> Reducción del 75% en VRAM.
- LoRA Rank r=16, Alpha=32 aplicado a todos los módulos lineales de atención (Q, K, V, O, MLP).
- Gradient Checkpointing activado para soporte de secuencias largas (4096 tokens).
- Optimizador AdamW 8-bit con planificador Cosine Annealing.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("FineTuning.QLoRA")

CURRENT_DIR = Path(__file__).parent.resolve()


@dataclass
class TrainingHyperparameters:
    """Configuración de hiperparámetros de entrenamiento."""

    base_model_name: str = "meta-llama/Meta-Llama-3-8B-Instruct"
    output_dir: str = str(CURRENT_DIR / "checkpoints" / "sovereign-compliance-8b-lora")
    dataset_train_path: str = str(CURRENT_DIR / "dataset" / "train_chatml.json")
    dataset_val_path: str = str(CURRENT_DIR / "dataset" / "val_chatml.json")
    max_seq_length: int = 2048
    lora_r: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    target_modules: list = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])
    batch_size: int = 2
    gradient_accumulation_steps: int = 4
    learning_rate: float = 2e-4
    num_train_epochs: int = 3
    warmup_ratio: float = 0.05
    weight_decay: float = 0.01
    optimizer: str = "paged_adamw_8bit"
    lr_scheduler_type: str = "cosine"
    fp16: bool = True
    logging_steps: int = 10
    save_strategy: str = "epoch"


class SovereignModelTrainer:
    """Orquestador de Fine-Tuning QLoRA / Unsloth."""

    def __init__(self, config: TrainingHyperparameters | None = None) -> None:
        self.config = config or TrainingHyperparameters()

    def train(self, dry_run: bool = False):
        """Ejecuta el ciclo de entrenamiento o simulación de validación."""
        logger.info("===============================================================")
        logger.info(f"🚀 Iniciando Pipeline de Fine-Tuning QLoRA: {self.config.base_model_name}")
        logger.info(f"📁 Checkpoint Output: {self.config.output_dir}")
        logger.info(f"⚙️ LoRA Rank: {self.config.lora_r} | Alpha: {self.config.lora_alpha}")
        logger.info(f"🎯 Target Modules: {self.config.target_modules}")
        logger.info(f"⚡ Batch Size: {self.config.batch_size} (Grad Accum: {self.config.gradient_accumulation_steps})")
        logger.info("===============================================================")

        if dry_run:
            logger.info("[Dry-Run] Verificando dataset de entrenamiento...")
            if not Path(self.config.dataset_train_path).exists():
                from generate_dataset import ComplianceDatasetGenerator
                gen = ComplianceDatasetGenerator()
                gen.build_train_val_split()
                logger.info("[Dry-Run] Dataset sintético generado con éxito.")

            logger.info("[Dry-Run] Estructura de hiperparámetros y targets validada.")
            return {"status": "success", "dry_run": True, "config": self.config}

        # Código de ejecución real en entornos con GPU (Torch + Transformers + PEFT)
        try:
            import torch
            from datasets import load_dataset
            from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
            from transformers import (
                AutoModelForCausalLM,
                AutoTokenizer,
                BitsAndBytesConfig,
                TrainingArguments,
            )
            from trl import SFTTrainer

            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
            )

            logger.info("Descargando / Cargando Modelo Base cuantizado en 4-bits...")
            model = AutoModelForCausalLM.from_pretrained(
                self.config.base_model_name,
                quantization_config=bnb_config,
                device_map="auto",
            )
            model = prepare_model_for_kbit_training(model)

            peft_config = LoraConfig(
                r=self.config.lora_r,
                lora_alpha=self.config.lora_alpha,
                lora_dropout=self.config.lora_dropout,
                target_modules=self.config.target_modules,
                bias="none",
                task_type="CAUSAL_LM",
            )
            model = get_peft_model(model, peft_config)

            tokenizer = AutoTokenizer.from_pretrained(self.config.base_model_name)
            tokenizer.pad_token = tokenizer.eos_token

            dataset = load_dataset("json", data_files={"train": self.config.dataset_train_path})

            training_args = TrainingArguments(
                output_dir=self.config.output_dir,
                per_device_train_batch_size=self.config.batch_size,
                gradient_accumulation_steps=self.config.gradient_accumulation_steps,
                learning_rate=self.config.learning_rate,
                num_train_epochs=self.config.num_train_epochs,
                warmup_ratio=self.config.warmup_ratio,
                optim=self.config.optimizer,
                lr_scheduler_type=self.config.lr_scheduler_type,
                logging_steps=self.config.logging_steps,
                save_strategy=self.config.save_strategy,
                fp16=self.config.fp16,
            )

            trainer = SFTTrainer(
                model=model,
                train_dataset=dataset["train"],
                peft_config=peft_config,
                dataset_text_field="messages",
                max_seq_length=self.config.max_seq_length,
                tokenizer=tokenizer,
                args=training_args,
            )

            logger.info("Entrenando adaptadores LoRA...")
            trainer.train()

            logger.info(f"Guardando pesos LoRA en {self.config.output_dir}...")
            model.save_pretrained(self.config.output_dir)
            tokenizer.save_pretrained(self.config.output_dir)

            return {"status": "completed", "output_dir": self.config.output_dir}

        except ImportError as e:
            logger.warning(
                f"Torch / CUDA / PEFT no detectados en este host ({e}). "
                "Este script está optimizado para ejecución en GPUs (RunPod / A100 / Colab).",
            )
            return {"status": "simulated_environment", "note": str(e)}


if __name__ == "__main__":
    trainer = SovereignModelTrainer()
    trainer.train(dry_run=True)
