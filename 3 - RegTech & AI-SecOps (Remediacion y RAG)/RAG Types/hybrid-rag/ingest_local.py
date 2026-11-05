import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ingest_local.py — Pipeline RAG 100% Local y Soberano para Entornos de Alta Seguridad
===================================================================================
Arquitectura Principal de Software de IA & Ciberseguridad Enterprise.

Cumplimiento Regulatorio y Normativo:
- 100% LOCAL (Zero Trust): Sin dependencias de APIs externas (OpenAI/Anthropic). Garantía de
  soberanía del dato para ENS / RGPD / entornos críticos.
- CRA (Cyber Resilience Act) & NIS2: Inmunización de entradas, validación de rutas (Path Traversal/LFI),
  resolución estricta de enlaces simbólicos y control de DoS/Bomba de Descompresión (tamaño máximo).
- ENS Categoría Alta (España) & EU AI Act: Trazabilidad legal, linaje de datos immutable (SHA-256 en origen
  y por fragmento), auditoría mediante Structured JSON Logging con niveles de severidad y trace context.
- DORA (Digital Operational Resilience Act): Tolerancia a fallos, aislamiento de errores por documento.

RAG Performance:
- Modelos de Embeddings SOTA (State of the Art): BAAI/bge-m3 o all-MiniLM-L6-v2 local vía GPU/CPU.
- Chunking semántico consciente de tokens (tiktoken / fallback recursivo).
- Cargadores de documentos extensibles (TXT, MD, HTML, RST, PDF, DOCX).
- Procesamiento en lotes por concurrencia.
"""

import os
import sys

# Desactivar advertencias de symlinks de huggingface en Windows y paralelismo de tokenizers
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

import warnings
warnings.filterwarnings("ignore", message=".*HF_TOKEN.*")
warnings.filterwarnings("ignore", category=UserWarning, module="huggingface_hub")

import re
import json
import time
import math
import uuid
import hashlib
import logging
import asyncio
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Union

# ---------------------------------------------------------------------------
# DEPENDENCIAS OPCIONALES CON FALLBACKS DE PRODUCCIÓN
# ---------------------------------------------------------------------------
try:
    from sentence_transformers import SentenceTransformer
    import torch
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False

try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False

try:
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

try:
    import docx
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False


# ---------------------------------------------------------------------------
# STRUCTURED JSON LOGGER (ENS CATEGORÍA ALTA & TRAZABILIDAD)
# ---------------------------------------------------------------------------
class StructuredJSONFormatter(logging.Formatter):
    """Formateador de logs en formato JSON estructurado para SIEM / ENS Alta."""
    def format(self, record: logging.LogRecord) -> str:
        log_object = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_object.update(record.extra_fields)
            
        if record.exc_info:
            log_object["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_object, ensure_ascii=False)


def setup_logger(name: str = "RAGLocalPipeline", level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJSONFormatter())
    logger.addHandler(handler)
    return logger

logger = setup_logger()


def log_event(level: str, message: str, **kwargs):
    """Helper para emitir un evento de log con contexto de auditoría."""
    lvl = level.lower()
    if lvl == "warn":
        lvl = "warning"
    log_func = getattr(logger, lvl, logger.info)
    extra_record = {"extra_fields": kwargs}
    log_func(message, extra=extra_record)


# ---------------------------------------------------------------------------
# CIBERSEGURIDAD: SANITIZACIÓN DE RUTAS Y ARCHIVOS (CRA & NIS2 & ENS)
# ---------------------------------------------------------------------------
class PathSanitizer:
    """Módulo de protección frente a Path Traversal, LFI, Symlinks y Zip Bombs."""
    
    EXCLUDED_DIRS = {'.venv', 'venv', '.git', 'node_modules', 'dist', '__pycache__', '.pytest_cache'}
    SUPPORTED_EXTENSIONS = {'.txt', '.md', '.html', '.htm', '.rst', '.pdf', '.docx'}

    @classmethod
    def sanitize_dir_path(cls, dir_path: Union[str, Path]) -> Path:
        resolved = Path(dir_path).resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"El directorio no existe: {resolved}")
        if not resolved.is_dir():
            raise NotADirectoryError(f"La ruta especificada no es un directorio: {resolved}")
        return resolved

    @classmethod
    def is_safe_path(cls, file_path: Path, base_dir: Path, max_file_size_mb: float = 10.0) -> Tuple[bool, str]:
        try:
            resolved_file = file_path.resolve()
            
            # Path Traversal Defense
            if base_dir not in resolved_file.parents and resolved_file != base_dir:
                return False, f"Path traversal detectado fuera del directorio base: {file_path}"
                
            # Symlink Defense
            if file_path.is_symlink():
                target = file_path.readlink()
                log_event("WARN", "Enlace simbólico detectado y omitido por seguridad", path=str(file_path), target=str(target))
                return False, "Symlinks deshabilitados por normativa"
                
            # Directory Exclusion
            for part in file_path.parts:
                if part in cls.EXCLUDED_DIRS:
                    return False, f"Directorio excluido: {part}"

            # Extension Check
            if file_path.suffix.lower() not in cls.SUPPORTED_EXTENSIONS:
                return False, f"Extensión no soportada: {file_path.suffix}"

            # File Size Check
            stat = resolved_file.stat()
            max_bytes = max_file_size_mb * 1024 * 1024
            if stat.st_size > max_bytes:
                return False, f"Tamaño del archivo excede el máximo permitido ({max_file_size_mb} MB)"

            return True, "OK"
        except Exception as e:
            return False, f"Error validando ruta: {str(e)}"


# ---------------------------------------------------------------------------
# CARGADORES DE DOCUMENTOS EXTENSIBLES (LOADERS)
# ---------------------------------------------------------------------------
class BaseDocumentLoader:
    def load(self, file_path: Path) -> str:
        raise NotImplementedError

class TextDocumentLoader(BaseDocumentLoader):
    def load(self, file_path: Path) -> str:
        for enc in ['utf-8', 'latin-1', 'cp1252']:
            try:
                with open(file_path, 'r', encoding=enc) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()

class MarkdownDocumentLoader(TextDocumentLoader):
    def load(self, file_path: Path) -> str:
        content = super().load(file_path)
        if content.startswith('---'):
            parts = content.split('---', 2)
            if len(parts) >= 3:
                content = parts[2]
        return content.strip()

class HtmlDocumentLoader(TextDocumentLoader):
    def load(self, file_path: Path) -> str:
        raw_html = super().load(file_path)
        text = re.sub(r'<script[\s\S]*?</script>', '', raw_html)
        text = re.sub(r'<style[\s\S]*?</style>', '', text)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

class PdfDocumentLoader(BaseDocumentLoader):
    def load(self, file_path: Path) -> str:
        if not PYPDF_AVAILABLE:
            log_event("WARNING", "pypdf no instalada. Omitiendo PDF", file=str(file_path))
            return ""
        text = ""
        try:
            reader = PdfReader(str(file_path))
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        except Exception as e:
            log_event("ERROR", "Fallo leyendo PDF", file=str(file_path), error=str(e))
        return text.strip()

class DocxDocumentLoader(BaseDocumentLoader):
    def load(self, file_path: Path) -> str:
        if not DOCX_AVAILABLE:
            log_event("WARNING", "python-docx no instalada. Omitiendo DOCX", file=str(file_path))
            return ""
        try:
            doc = docx.Document(str(file_path))
            return "\n".join([p.text for p in doc.paragraphs if p.text])
        except Exception as e:
            log_event("ERROR", "Fallo leyendo DOCX", file=str(file_path), error=str(e))
            return ""

class DocumentLoaderFactory:
    _LOADERS = {
        '.txt': TextDocumentLoader(),
        '.md': MarkdownDocumentLoader(),
        '.rst': TextDocumentLoader(),
        '.html': HtmlDocumentLoader(),
        '.htm': HtmlDocumentLoader(),
        '.pdf': PdfDocumentLoader(),
        '.docx': DocxDocumentLoader()
    }
    @classmethod
    def get_loader(cls, extension: str) -> BaseDocumentLoader:
        return cls._LOADERS.get(extension.lower(), TextDocumentLoader())


# ---------------------------------------------------------------------------
# CHUNKING PROFESIONAL Y CONSCIENTE DE TOKENS / PÁRRAFOS
# ---------------------------------------------------------------------------
class TokenSemanticSplitter:
    def __init__(self, chunk_size: int = 300, chunk_overlap: int = 50, encoding_name: str = "cl100k_base"):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.tokenizer = None
        if TIKTOKEN_AVAILABLE:
            try:
                self.tokenizer = tiktoken.get_encoding(encoding_name)
            except Exception:
                pass

    def count_tokens(self, text: str) -> int:
        if self.tokenizer:
            return len(self.tokenizer.encode(text))
        return math.ceil(len(text) / 4)

    def split_text(self, text: str) -> List[str]:
        if not text.strip():
            return []
            
        paragraphs = text.split("\n\n")
        chunks = []
        current_chunk_words = []
        current_tokens = 0
        
        for para in paragraphs:
            para_words = para.split()
            para_tokens = self.count_tokens(para)
            
            if current_tokens + para_tokens <= self.chunk_size:
                current_chunk_words.extend(para_words)
                current_tokens += para_tokens
            else:
                for word in para_words:
                    word_tokens = self.count_tokens(word)
                    if current_tokens + word_tokens > self.chunk_size and current_chunk_words:
                        chunk_str = " ".join(current_chunk_words)
                        chunks.append(chunk_str)
                        
                        overlap_words = []
                        overlap_tok_count = 0
                        for w in reversed(current_chunk_words):
                            wt = self.count_tokens(w)
                            if overlap_tok_count + wt <= self.chunk_overlap:
                                overlap_words.insert(0, w)
                                overlap_tok_count += wt
                            else:
                                break
                        current_chunk_words = overlap_words + [word]
                        current_tokens = overlap_tok_count + word_tokens
                    else:
                        current_chunk_words.append(word)
                        current_tokens += word_tokens
                        
        if current_chunk_words:
            chunks.append(" ".join(current_chunk_words))
            
        return chunks


# ---------------------------------------------------------------------------
# EMBEDDINGS 100% LOCALES (SIN APIS EXTERNAS)
# ---------------------------------------------------------------------------
class LocalEmbeddingProvider:
    """Proveedor de Embeddings Local usando sentence-transformers."""
    def __init__(self, model_name: str = "BAAI/bge-m3"):
        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            log_event("ERROR", "sentence-transformers no está instalado. No se pueden generar embeddings.")
            raise ImportError("Instala 'sentence-transformers' y 'torch' para ejecutar en local.")
        
        # Detección de hardware: CUDA > MPS (Apple Silicon) > CPU
        if torch.cuda.is_available():
            self.device = "cuda"
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            self.device = "mps"
        else:
            self.device = "cpu"
            
        log_event("INFO", f"Cargando modelo de embeddings '{model_name}' en dispositivo: {self.device}")
        
        # Carga del modelo en memoria
        self.model = SentenceTransformer(model_name, device=self.device)

    async def generate_embeddings_batch(self, texts: List[str]) -> List[List[float]]:
        # La inferencia se realiza en un hilo separado para no bloquear el loop asyncio
        def _encode():
            embeddings = self.model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
            return embeddings.tolist()
            
        return await asyncio.to_thread(_encode)


# ---------------------------------------------------------------------------
# PIPELINE PRINCIPAL DE INGESTA RAG
# ---------------------------------------------------------------------------
class RAGLocalIngestionPipeline:
    def __init__(self, source_dir: Path, output_file: Path, chunk_size: int = 300,
                 chunk_overlap: int = 50, max_file_size_mb: float = 10.0,
                 model_name: str = "BAAI/bge-m3", batch_size: int = 32, trace_id: Optional[str] = None):
        self.source_dir = PathSanitizer.sanitize_dir_path(source_dir)
        self.output_file = Path(output_file).resolve()
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.max_file_size_mb = max_file_size_mb
        self.batch_size = batch_size
        self.trace_id = trace_id or str(uuid.uuid4())
        
        self.splitter = TokenSemanticSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        self.embedding_provider = LocalEmbeddingProvider(model_name=model_name)

    async def run(self) -> Dict[str, Any]:
        start_time = time.time()
        log_event("INFO", "Iniciando Pipeline de Ingesta RAG 100% LOCAL",
                  trace_id=self.trace_id, source_dir=str(self.source_dir))
                  
        scanned_files = processed_files = skipped_files = failed_files = total_bytes = 0
        processed_records: List[Dict[str, Any]] = []

        # 1. Escaneo seguro
        all_filepaths: List[Path] = []
        for root, _, files in os.walk(self.source_dir):
            for file_name in files:
                scanned_files += 1
                full_p = Path(root) / file_name
                is_safe, reason = PathSanitizer.is_safe_path(full_p, self.source_dir, self.max_file_size_mb)
                if is_safe:
                    all_filepaths.append(full_p)
                else:
                    skipped_files += 1
                    log_event("INFO", "Archivo omitido", path=str(full_p), reason=reason)

        log_event("INFO", f"Archivos aptos para procesamiento: {len(all_filepaths)}", trace_id=self.trace_id)

        # 2. Procesamiento aislado documento a documento
        for file_path in all_filepaths:
            try:
                rel_path = file_path.relative_to(self.source_dir).as_posix()
                loader = DocumentLoaderFactory.get_loader(file_path.suffix)
                
                raw_content = loader.load(file_path)
                if not raw_content or not raw_content.strip():
                    skipped_files += 1
                    continue
                    
                file_bytes = len(raw_content.encode('utf-8'))
                total_bytes += file_bytes
                
                # Linaje y Trazabilidad (SHA-256)
                doc_sha256 = hashlib.sha256(raw_content.encode('utf-8')).hexdigest()
                
                text_chunks = self.splitter.split_text(raw_content)
                if not text_chunks:
                    skipped_files += 1
                    continue

                # Inferencia Local por lotes
                chunk_embeddings = []
                for i in range(0, len(text_chunks), self.batch_size):
                    batch_texts = text_chunks[i:i + self.batch_size]
                    batch_vecs = await self.embedding_provider.generate_embeddings_batch(batch_texts)
                    chunk_embeddings.extend(batch_vecs)

                now_iso = datetime.now(timezone.utc).isoformat()
                for idx, (chunk_text, embedding_vec) in enumerate(zip(text_chunks, chunk_embeddings)):
                    chunk_sha256 = hashlib.sha256(chunk_text.encode('utf-8')).hexdigest()
                    chunk_id = hashlib.sha256(f"{doc_sha256}:{idx}:{chunk_sha256}".encode('utf-8')).hexdigest()
                    
                    record = {
                        "id": chunk_id,
                        "source_file": rel_path,
                        "chunk_index": idx,
                        "content": chunk_text,
                        "metadata": {
                            "doc_sha256": doc_sha256,
                            "chunk_sha256": chunk_sha256,
                            "file_size_bytes": file_bytes,
                            "token_count": self.splitter.count_tokens(chunk_text),
                            "processed_at": now_iso,
                            "trace_id": self.trace_id
                        },
                        "embedding": embedding_vec
                    }
                    processed_records.append(record)

                processed_files += 1
                log_event("INFO", "Documento vectorizado", source=rel_path, chunks=len(text_chunks))
                          
            except Exception as e:
                failed_files += 1
                log_event("ERROR", f"Fallo procesando archivo: {file_path}", error=str(e), exc_info=True)

        # 3. Escritura Atómica
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        temp_output = self.output_file.with_suffix(".tmp")
        try:
            with open(temp_output, "w", encoding="utf-8") as f:
                json.dump(processed_records, f, indent=2, ensure_ascii=False)
            temp_output.replace(self.output_file)
        except Exception as e:
            if temp_output.exists():
                temp_output.unlink()
            raise IOError(f"Error escribiendo JSON de salida: {e}")

        duration = time.time() - start_time
        summary = {
            "trace_id": self.trace_id,
            "processed_files": processed_files,
            "failed_files": failed_files,
            "total_chunks": len(processed_records),
            "duration_seconds": round(duration, 3),
            "status": "SUCCESS" if failed_files == 0 else "PARTIAL_SUCCESS"
        }
        
        log_event("INFO", "Ejecución local finalizada", **summary)
        return summary


# ---------------------------------------------------------------------------
# CLI Y EJECUCIÓN
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Pipeline RAG 100% LOCAL (Soberanía de Datos / ENS).")
    parser.add_argument("-d", "--dir", required=True, help="Directorio raíz de documentos.")
    parser.add_argument("-o", "--output", default="./rag_local_embeddings.json", help="JSON de salida.")
    parser.add_argument("--size", type=int, default=300, help="Tamaño de chunk (tokens).")
    parser.add_argument("--overlap", type=int, default=50, help="Solapamiento (tokens).")
    parser.add_argument("--model", default="sentence-transformers/all-MiniLM-L6-v2", 
                        help="Modelo de HuggingFace (ej. BAAI/bge-m3 o all-MiniLM-L6-v2).")
    parser.add_argument("--batch-size", type=int, default=16, help="Tamaño de batch inferencia.")

    args = parser.parse_args()
    
    try:
        pipeline = RAGLocalIngestionPipeline(
            source_dir=Path(args.dir),
            output_file=Path(args.output),
            chunk_size=args.size,
            chunk_overlap=args.overlap,
            model_name=args.model,
            batch_size=args.batch_size
        )
        
        summary = asyncio.run(pipeline.run())
        
        print("\n" + "="*60)
        print(" PIPELINE RAG LOCAL FINALIZADO")
        print("="*60)
        print(f" Archivos procesados: {summary['processed_files']}")
        print(f" Chunks generados:    {summary['total_chunks']}")
        print(f" Tiempo ejecución:    {summary['duration_seconds']} s")
        print(f" Estado:              {summary['status']}")
        print("="*60 + "\n")
        
    except Exception as e:
        log_event("ERROR", "Pipeline abortado", error=str(e), exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
