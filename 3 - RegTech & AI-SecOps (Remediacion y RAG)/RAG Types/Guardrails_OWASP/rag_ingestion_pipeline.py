#!/usr/bin/env python3
"""
rag_ingestion_pipeline.py — Pipeline Enterprise de Ingesta RAG (Retrieval-Augmented Generation)
=============================================================================================
Arquitectura Principal de Software de IA & Ciberseguridad Enterprise.

Cumplimiento Regulatorio y Normativo:
- CRA (Cyber Resilience Act) & NIS2: Inmunización de entradas, validación de rutas (Path Traversal/LFI),
  resolución estricta de enlaces simbólicos y control de DoS/Bomba de Descompresión (tamaño máximo).
- ENS Categoría Alta (España) & eu-ai-act-module: Trazabilidad legal, linaje de datos immutable (SHA-256 en origen
  y por fragmento), auditoría mediante Structured JSON Logging con niveles de severidad y trace context.
- DORA (Digital Operational Resilience Act): Tolerancia a fallos, aislamiento de errores por documento
  y reintentos exponenciales con jitter (Exponential Backoff).
- RGPD / LOPDGDD: Módulo de anonimización / PII Masking automático previa a la generación de embeddings.

RAG Performance:
- Chunking semántico consciente de tokens (tiktoken / fallback recursivo).
- Embeddings multiproveedor asíncronos (OpenAI API, Ollama, Mock determinista para offline).
- Cargadores de documentos extensibles (TXT, MD, HTML, RST, PDF, DOCX).
- Procesamiento en lotes por concurrencia (asyncio Batching).
"""

import logging
import os

from dotenv import load_dotenv

load_dotenv()  # Zero Trust — carga segura de variables de entorno locales (ENS / DORA)

import argparse
import asyncio
import contextlib
import hashlib
import json
import math
import random
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

# ---------------------------------------------------------------------------
# DEPENDENCIAS OPCIONALES CON FALLBACKS DE PRODUCCIÓN
# ---------------------------------------------------------------------------
try:
    from pydantic import BaseModel
    from pydantic_settings import BaseSettings
    PYDANTIC_AVAILABLE = True
except ImportError:
    try:
        from pydantic import BaseModel  # type: ignore[assignment]
        class BaseSettings(BaseModel):  # type: ignore[no-redef]
            pass
        PYDANTIC_AVAILABLE = True
    except ImportError:
        PYDANTIC_AVAILABLE = False

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
            "line": record.lineno,
        }
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_object.update(record.extra_fields)

        if record.exc_info:
            log_object["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_object, ensure_ascii=False)


def setup_logger(name: str = "RAGPipeline", level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJSONFormatter())
    logger.addHandler(handler)
    return logger

logger = setup_logger()


def log_event(level: str, message: str, **kwargs) -> None:
    """Helper para emitir un evento de log con contexto de auditoría."""
    lvl = level.lower()
    if lvl == "warn":
        lvl = "warning"
    log_func = getattr(logger, lvl, logger.info)
    extra_record = {"extra_fields": kwargs}
    log_func(message, extra=extra_record)


# ---------------------------------------------------------------------------
# MODELOS DE DATOS Y ESQUEMAS TIPADOS (PYDANTIC / FALLBACK DATACLASS)
# ---------------------------------------------------------------------------
if PYDANTIC_AVAILABLE:
    class DocumentMetadataSchema(BaseModel):
        source_path: str
        source_sha256: str
        file_size_bytes: int
        processed_at: str
        mime_type: str
        pii_masked: bool

    class ChunkMetadataSchema(BaseModel):
        doc_sha256: str
        chunk_sha256: str
        chunk_index: int
        token_count: int
        char_count: int
        processed_at: str

    class ChunkRecordSchema(BaseModel):
        id: str
        source_file: str
        chunk_index: int
        content: str
        metadata: dict[str, Any]
        embedding: list[float]

    class ExecutionSummarySchema(BaseModel):
        trace_id: str
        total_files_scanned: int
        processed_files: int
        skipped_files: int
        failed_files: int
        total_chunks: int
        total_bytes_processed: int
        duration_seconds: float
        status: str
else:
    class DocumentMetadataSchema:  # type: ignore[no-redef]
        def __init__(self, source_path: str, source_sha256: str, file_size_bytes: int,
                     processed_at: str, mime_type: str, pii_masked: bool) -> None:
            self.source_path = source_path
            self.source_sha256 = source_sha256
            self.file_size_bytes = file_size_bytes
            self.processed_at = processed_at
            self.mime_type = mime_type
            self.pii_masked = pii_masked

        def dict(self) -> dict[str, Any]:
            return self.__dict__

    class ChunkMetadataSchema:  # type: ignore[no-redef]
        def __init__(self, doc_sha256: str, chunk_sha256: str, chunk_index: int,
                     token_count: int, char_count: int, processed_at: str) -> None:
            self.doc_sha256 = doc_sha256
            self.chunk_sha256 = chunk_sha256
            self.chunk_index = chunk_index
            self.token_count = token_count
            self.char_count = char_count
            self.processed_at = processed_at

        def dict(self) -> dict[str, Any]:
            return self.__dict__


# ---------------------------------------------------------------------------
# CIBERSEGURIDAD: SANITIZACIÓN DE RUTAS Y ARCHIVOS (CRA & NIS2 & ENS)
# ---------------------------------------------------------------------------
class PathSanitizer:
    """Módulo de protección frente a Path Traversal, LFI, Symlinks y Zip Bombs."""

    EXCLUDED_DIRS: ClassVar[set[str]] = {".venv", "venv", ".git", "node_modules", "dist", "__pycache__", ".pytest_cache"}
    SUPPORTED_EXTENSIONS: ClassVar[set[str]] = {".txt", ".md", ".html", ".htm", ".rst", ".pdf", ".docx"}

    @classmethod
    def sanitize_dir_path(cls, dir_path: str | Path) -> Path:
        """Valida y resuelve de forma absoluta la ruta del directorio base."""
        resolved = Path(dir_path).resolve()
        if not resolved.exists():
            msg = f"El directorio no existe: {resolved}"
            raise FileNotFoundError(msg)
        if not resolved.is_dir():
            msg = f"La ruta especificada no es un directorio: {resolved}"
            raise NotADirectoryError(msg)
        return resolved

    @classmethod
    def is_safe_path(cls, file_path: Path, base_dir: Path, max_file_size_mb: float = 10.0) -> tuple[bool, str]:
        """Garantiza que el archivo pertenece al directorio base, no es un enlace
        simbólico malicioso y no excede el tamaño máximo permitido.
        """
        try:
            resolved_file = file_path.resolve()

            # 1. Path Traversal & LFI Defense
            if base_dir not in resolved_file.parents and resolved_file != base_dir:
                return False, f"Path traversal detectado fuera del directorio base: {file_path}"

            # 2. Symlink Defense
            if file_path.is_symlink():
                target = file_path.readlink()
                log_event("WARN", "Enlace simbólico detectado y omitido por seguridad", path=str(file_path), target=str(target))
                return False, "Symlinks deshabilitados por normativa NIS2/ENS"

            # 3. Directory Exclusion Filter
            for part in file_path.parts:
                if part in cls.EXCLUDED_DIRS:
                    return False, f"Directorio excluido: {part}"

            # 4. Extension Check
            if file_path.suffix.lower() not in cls.SUPPORTED_EXTENSIONS:
                return False, f"Extensión no soportada: {file_path.suffix}"

            # 5. Bomb / DoS File Size Check
            stat = resolved_file.stat()
            max_bytes = max_file_size_mb * 1024 * 1024
            if stat.st_size > max_bytes:
                return False, f"Tamaño del archivo ({stat.st_size} bytes) excede el máximo ({max_bytes} bytes)"

            return True, "OK"
        except (OSError, ValueError, RuntimeError) as e:
            return False, f"Error de seguridad validando ruta: {e!s}"


# ---------------------------------------------------------------------------
# PROTECCIÓN DE DATOS: MÓDULO DE ANONIMIZACIÓN PII (RGPD / LOPDGDD)
# ---------------------------------------------------------------------------
class PIIMasker:
    """Módulo de enmascaramiento de Datos de Carácter Personal (PII) para España/EU."""

    # Patrón DNI / NIE Español
    DNI_NIE_PATTERN = re.compile(r"\b[XYZ]?\d{7,8}[A-Z]\b", re.IGNORECASE)
    # Emails
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    # Teléfonos España
    PHONE_PATTERN = re.compile(r"\b(?:\+34\s?|34\s?)?[6789]\d{2}(?:\s?\d{3}){2}\b")
    # Direcciones IP v4
    IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    @classmethod
    def mask(cls, text: str) -> str:
        """Sustituye datos personales por etiquetas anónimas estandarizadas."""
        if not text:
            return ""
        text = cls.DNI_NIE_PATTERN.sub("[REDACTED_DNI_NIE]", text)
        text = cls.EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
        text = cls.PHONE_PATTERN.sub("[REDACTED_PHONE]", text)
        return cls.IP_PATTERN.sub("[REDACTED_IP]", text)


# ---------------------------------------------------------------------------
# CARGADORES DE DOCUMENTOS EXTENSIBLES (LOADERS)
# ---------------------------------------------------------------------------
class BaseDocumentLoader:
    """Interfaz base para cargadores de documentos."""

    def load(self, file_path: Path) -> str:
        raise NotImplementedError

class TextDocumentLoader(BaseDocumentLoader):
    def load(self, file_path: Path) -> str:
        encodings = ["utf-8", "latin-1", "cp1252"]
        for enc in encodings:
            try:
                with open(file_path, encoding=enc) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            return f.read()

class MarkdownDocumentLoader(TextDocumentLoader):
    def load(self, file_path: Path) -> str:
        content = super().load(file_path)
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                content = parts[2]
        return content.strip()

class HtmlDocumentLoader(TextDocumentLoader):
    def load(self, file_path: Path) -> str:
        raw_html = super().load(file_path)
        text = re.sub(r"<script[\s\S]*?</script>", "", raw_html)
        text = re.sub(r"<style[\s\S]*?</style>", "", text)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

class PdfDocumentLoader(BaseDocumentLoader):
    def load(self, file_path: Path) -> str:
        if not PYPDF_AVAILABLE:
            log_event("WARN", "librería 'pypdf' no instalada. Omitiendo extracción avanzada de PDF", file=str(file_path))
            return ""
        text = ""
        try:
            reader = PdfReader(str(file_path))
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        except (OSError, ValueError, RuntimeError) as e:
            log_event("ERROR", "Fallo leyendo PDF", file=str(file_path), error=str(e))
        return text.strip()

class DocxDocumentLoader(BaseDocumentLoader):
    def load(self, file_path: Path) -> str:
        if not DOCX_AVAILABLE:
            log_event("WARN", "librería 'python-docx' no instalada. Omitiendo lectura DOCX", file=str(file_path))
            return ""
        try:
            doc = docx.Document(str(file_path))
            return "\n".join([p.text for p in doc.paragraphs if p.text])
        except (OSError, ValueError, RuntimeError) as e:
            log_event("ERROR", "Fallo leyendo DOCX", file=str(file_path), error=str(e))
            return ""

class DocumentLoaderFactory:
    """Factoría de cargadores según extensión."""

    _LOADERS: ClassVar[dict[str, "BaseDocumentLoader"]] = {
        ".txt": TextDocumentLoader(),
        ".md": MarkdownDocumentLoader(),
        ".rst": TextDocumentLoader(),
        ".html": HtmlDocumentLoader(),
        ".htm": HtmlDocumentLoader(),
        ".pdf": PdfDocumentLoader(),
        ".docx": DocxDocumentLoader(),
    }

    @classmethod
    def get_loader(cls, extension: str) -> BaseDocumentLoader:
        return cls._LOADERS.get(extension.lower(), TextDocumentLoader())


# ---------------------------------------------------------------------------
# CHUNKING PROFESIONAL Y CONSCIENTE DE TOKENS
# ---------------------------------------------------------------------------
class TokenSemanticSplitter:
    """Splitter de texto basado en recuento de tokens (tiktoken o aproximado) y párrafos."""

    def __init__(self, chunk_size: int = 300, chunk_overlap: int = 50, encoding_name: str = "cl100k_base") -> None:
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.tokenizer = None
        if TIKTOKEN_AVAILABLE:
            with contextlib.suppress(Exception):
                self.tokenizer = tiktoken.get_encoding(encoding_name)

    def count_tokens(self, text: str) -> int:
        if self.tokenizer:
            return len(self.tokenizer.encode(text))
        return math.ceil(len(text) / 4)

    def split_text(self, text: str) -> list[str]:
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

                        overlap_words: list[str] = []
                        overlap_tok_count = 0
                        for w in reversed(current_chunk_words):
                            wt = self.count_tokens(w)
                            if overlap_tok_count + wt <= self.chunk_overlap:
                                overlap_words.insert(0, w)
                                overlap_tok_count += wt
                            else:
                                break
                        current_chunk_words = [*overlap_words, word]
                        current_tokens = overlap_tok_count + word_tokens
                    else:
                        current_chunk_words.append(word)
                        current_tokens += word_tokens

        if current_chunk_words:
            chunks.append(" ".join(current_chunk_words))

        return chunks


# ---------------------------------------------------------------------------
# RESILIENCIA Y ASYNC EMBEDDING PROVIDERS (DORA & REAL EMBEDDINGS)
# ---------------------------------------------------------------------------
def async_retry(max_retries: int = 3, initial_delay: float = 1.0, backoff_factor: float = 2.0):
    """Decorador de reintentos exponenciales con jitter para operaciones asíncronas de red."""
    def decorator(func: Callable):
        async def wrapper(*args, **kwargs):
            delay = initial_delay
            for attempt in range(1, max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries:
                        log_event("ERROR", "Reintentos agotados para la llamada a la API", attempt=attempt, error=str(e))
                        raise
                    jitter = random.uniform(0, 0.5)
                    sleep_time = delay + jitter
                    log_event("WARN", f"Fallo en intento {attempt}/{max_retries}. Reintentando en {sleep_time:.2f}s...", error=str(e))
                    await asyncio.sleep(sleep_time)
                    delay *= backoff_factor
            return None
        return wrapper
    return decorator


class BaseEmbeddingProvider:
    async def generate_embeddings_batch(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError


class MockEmbeddingProvider(BaseEmbeddingProvider):
    """Proveedor determinista offline basado en SHA-256 para testing y fallback sin coste API."""

    async def generate_embeddings_batch(self, texts: list[str]) -> list[list[float]]:
        results = []
        for text in texts:
            sha = hashlib.sha256(text.encode("utf-8")).digest()
            vector = []
            for j in range(1536):
                byte_val = sha[j % len(sha)]
                val = (byte_val / 127.5) - 1.0
                vector.append(round(val, 6))
            results.append(vector)
        return results


class OpenAIEmbeddingProvider(BaseEmbeddingProvider):
    """Cliente para la API de Embeddings de OpenAI con reintentos y compatibilidad con urllib."""

    def __init__(self, api_key: str, model: str = "text-embedding-3-small") -> None:
        self.api_key = api_key
        self.model = model
        self.url = "https://api.openai.com/v1/embeddings"

    @async_retry(max_retries=3)
    async def _call_api(self, texts: list[str]) -> list[list[float]]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = json.dumps({"input": texts, "model": self.model}).encode("utf-8")

        req = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")

        def _execute():
            # ENS Alta / OWASP A10 (SSRF): validate URL scheme before opening
            _allowed_schemes = ("https://", "http://localhost", "http://127.")
            req_url = req.full_url if hasattr(req, "full_url") else str(req)
            if not any(req_url.startswith(scheme) for scheme in _allowed_schemes):
                raise ValueError(f"URL scheme rechazado (SSRF guard): {req_url}")
            with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
                return json.loads(resp.read().decode("utf-8"))

        data = await asyncio.to_thread(_execute)
        return [item["embedding"] for item in data["data"]]

    async def generate_embeddings_batch(self, texts: list[str]) -> list[list[float]]:
        return await self._call_api(texts)


class OllamaEmbeddingProvider(BaseEmbeddingProvider):
    """Cliente para servidor Ollama local (ej. nomic-embed-text)."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "nomic-embed-text") -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model

    @async_retry(max_retries=3)
    async def _call_ollama_single(self, text: str) -> list[float]:
        url = f"{self.base_url}/api/embeddings"
        payload = json.dumps({"model": self.model, "prompt": text}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

        def _execute():
            # ENS Alta / OWASP A10 (SSRF): validate URL scheme before opening
            _allowed_schemes = ("https://", "http://localhost", "http://127.")
            req_url = req.full_url if hasattr(req, "full_url") else str(req)
            if not any(req_url.startswith(scheme) for scheme in _allowed_schemes):
                raise ValueError(f"URL scheme rechazado (SSRF guard): {req_url}")
            with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
                return json.loads(resp.read().decode("utf-8"))

        data = await asyncio.to_thread(_execute)
        return data["embedding"]

    async def generate_embeddings_batch(self, texts: list[str]) -> list[list[float]]:
        tasks = [self._call_ollama_single(text) for text in texts]
        return await asyncio.gather(*tasks)


# ---------------------------------------------------------------------------
# PIPELINE PRINCIPAL DE INGESTA RAG ENTERPRISE
# ---------------------------------------------------------------------------
def _write_json_sync(file_path: Path, data: list) -> None:
    """Escritura sincrónica de JSON — llamada desde asyncio.run_in_executor para no bloquear el event loop."""
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


class RAGIngestionPipeline:
    """Orquestador principal del pipeline RAG con aislamiento de errores por documento."""

    def __init__(self, source_dir: Path, output_file: Path, chunk_size: int = 300,
                 chunk_overlap: int = 50, max_file_size_mb: float = 10.0,
                 mask_pii: bool = False, provider_name: str = "mock",
                 openai_api_key: str | None = None, ollama_url: str = "http://localhost:11434",
                 batch_size: int = 32, trace_id: str | None = None) -> None:
        self.source_dir = PathSanitizer.sanitize_dir_path(source_dir)
        self.output_file = Path(output_file).resolve()
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.max_file_size_mb = max_file_size_mb
        self.mask_pii = mask_pii
        self.batch_size = batch_size
        self.trace_id = trace_id or str(uuid.uuid4())

        self.splitter = TokenSemanticSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        self.embedding_provider: BaseEmbeddingProvider = MockEmbeddingProvider()

        if provider_name == "openai":
            api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
            if not api_key:
                log_event("WARN", "OPENAI_API_KEY no encontrada. Recurriendo al proveedor Mock determinista")
                self.embedding_provider = MockEmbeddingProvider()
            else:
                self.embedding_provider = OpenAIEmbeddingProvider(api_key=api_key)
        elif provider_name == "ollama":
            self.embedding_provider = OllamaEmbeddingProvider(base_url=ollama_url)
        else:
            self.embedding_provider = MockEmbeddingProvider()

    async def run(self) -> dict[str, Any]:
        start_time = time.time()
        log_event("INFO", "Iniciando Pipeline de Ingesta RAG Enterprise",
                  trace_id=self.trace_id, source_dir=str(self.source_dir), mask_pii=self.mask_pii)

        scanned_files = 0
        processed_files = 0
        skipped_files = 0
        failed_files = 0
        total_bytes = 0

        processed_records: list[dict[str, Any]] = []

        # 1. Escaneo seguro de directorios
        all_filepaths: list[Path] = []
        for root, _, files in os.walk(self.source_dir):
            for file_name in files:
                scanned_files += 1
                full_p = Path(root) / file_name
                is_safe, reason = PathSanitizer.is_safe_path(full_p, self.source_dir, self.max_file_size_mb)
                if is_safe:
                    all_filepaths.append(full_p)
                else:
                    skipped_files += 1
                    log_event("INFO", "Archivo omitido en escaneo", path=str(full_p), reason=reason)

        log_event("INFO", f"Escaneo completado. Archivos aptos para procesamiento: {len(all_filepaths)}", trace_id=self.trace_id)

        # 2. Procesamiento aislado documento por documento (DORA Compliance)
        for file_path in all_filepaths:
            try:
                rel_path = file_path.relative_to(self.source_dir).as_posix()
                loader = DocumentLoaderFactory.get_loader(file_path.suffix)

                raw_content = loader.load(file_path)
                if not raw_content or not raw_content.strip():
                    skipped_files += 1
                    continue

                file_bytes = len(raw_content.encode("utf-8"))
                total_bytes += file_bytes

                # Linaje y Checksum de Origen (SHA-256)
                doc_sha256 = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()

                # Módulo de Anonimización / PII Masking (RGPD)
                content_to_process = raw_content
                if self.mask_pii:
                    content_to_process = PIIMasker.mask(raw_content)

                # Chunking semántico
                text_chunks = self.splitter.split_text(content_to_process)
                if not text_chunks:
                    skipped_files += 1
                    continue

                # Batch Processing
                chunk_embeddings = []
                for i in range(0, len(text_chunks), self.batch_size):
                    batch_texts = text_chunks[i:i + self.batch_size]
                    batch_vecs = await self.embedding_provider.generate_embeddings_batch(batch_texts)
                    chunk_embeddings.extend(batch_vecs)

                # Ensamblado de registros con Linaje de Datos completo (ENS Alta & AI Act)
                now_iso = datetime.now(timezone.utc).isoformat()
                for idx, (chunk_text, embedding_vec) in enumerate(zip(text_chunks, chunk_embeddings, strict=False)):
                    chunk_sha256 = hashlib.sha256(chunk_text.encode("utf-8")).hexdigest()
                    chunk_id = hashlib.sha256(f"{doc_sha256}:{idx}:{chunk_sha256}".encode()).hexdigest()

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
                            "char_count": len(chunk_text),
                            "processed_at": now_iso,
                            "pii_masked": self.mask_pii,
                            "trace_id": self.trace_id,
                        },
                        "embedding": embedding_vec,
                    }
                    processed_records.append(record)

                processed_files += 1
                log_event("INFO", "Documento procesado exitosamente",
                          source=rel_path, doc_sha256=doc_sha256, chunks=len(text_chunks))

            except (OSError, ValueError, RuntimeError, TypeError, UnicodeDecodeError) as e:
                failed_files += 1
                log_event("ERROR", f"Fallo aislado procesando archivo: {file_path}",
                          trace_id=self.trace_id, error=str(e), exc_info=True)

        # 3. Escritura Atómica del Archivo de Salida
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        temp_output = self.output_file.with_suffix(".tmp")
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: _write_json_sync(temp_output, processed_records),
            )
            temp_output.replace(self.output_file)
        except OSError as e:
            if temp_output.exists():
                temp_output.unlink()
            msg = f"Error escribiendo el manifiesto vectorial de salida: {e}"
            raise OSError(msg) from e

        duration = time.time() - start_time
        summary = {
            "trace_id": self.trace_id,
            "total_files_scanned": scanned_files,
            "processed_files": processed_files,
            "skipped_files": skipped_files,
            "failed_files": failed_files,
            "total_chunks": len(processed_records),
            "total_bytes_processed": total_bytes,
            "duration_seconds": round(duration, 3),
            "output_file": str(self.output_file),
            "status": "SUCCESS" if failed_files == 0 else "PARTIAL_SUCCESS",
        }

        log_event("INFO", "Ejecución finalizada del Pipeline RAG", **summary)
        return summary


# ---------------------------------------------------------------------------
# INTERFAZ DE LÍNEA DE COMANDOS ENTERPRISE (CLI)
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pipeline Enterprise RAG — Módulo seguro de ingesta vectorial conforme a DORA, NIS2, ENS Alta y RGPD.",
    )
    parser.add_argument("-d", "--dir", required=True, help="Directorio raíz de documentos de conocimiento.")
    parser.add_argument("-o", "--output", default="./rag_embeddings.json", help="Ruta del archivo JSON de salida.")
    parser.add_argument("--size", type=int, default=300, help="Tamaño objetivo de chunk en tokens (def: 300).")
    parser.add_argument("--overlap", type=int, default=50, help="Solapamiento de chunks en tokens (def: 50).")
    parser.add_argument("--max-file-size-mb", type=float, default=10.0, help="Límite máximo de tamaño por archivo en MB (def: 10.0).")
    parser.add_argument("--mask-pii", action="store_true", help="Activa la anonimización/enmascaramiento PII (RGPD).")
    parser.add_argument("--provider", choices=["mock", "openai", "ollama"], default="mock", help="Proveedor de Embeddings (def: mock).")
    parser.add_argument("--openai-key", default=None, help="API Key de OpenAI (o usar env variable OPENAI_API_KEY).")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="URL base para servidor Ollama.")
    parser.add_argument("--batch-size", type=int, default=32, help="Tamaño de lote para vectorización (def: 32).")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARN", "ERROR"], default="INFO", help="Nivel del Logger JSON.")

    args = parser.parse_args()

    global logger
    logger = setup_logger(level=args.log_level)

    try:
        pipeline = RAGIngestionPipeline(
            source_dir=Path(args.dir),
            output_file=Path(args.output),
            chunk_size=args.size,
            chunk_overlap=args.overlap,
            max_file_size_mb=args.max_file_size_mb,
            mask_pii=args.mask_pii,
            provider_name=args.provider,
            openai_api_key=args.openai_key,
            ollama_url=args.ollama_url,
            batch_size=args.batch_size,
        )

        asyncio.run(pipeline.run())


    except (OSError, ValueError, RuntimeError, asyncio.CancelledError) as e:
        log_event("ERROR", "Error crítico deteniendo la ejecución del pipeline", error=str(e), exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
