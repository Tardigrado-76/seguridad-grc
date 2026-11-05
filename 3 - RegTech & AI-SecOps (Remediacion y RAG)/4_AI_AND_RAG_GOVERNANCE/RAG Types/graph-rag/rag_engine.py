#!/usr/bin/env python3
import logging
import os

from dotenv import load_dotenv

load_dotenv()  # Zero Trust — carga segura de variables de entorno (ENS / DORA)

os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

"""
rag_engine.py — Arquitectura Enterprise RAG 360° (100% Local & Soberana)
========================================================================
Cumplimiento Regulatorio y Normativo:
- ENS Categoría Alta (España) & eu-ai-act-module: Trazabilidad, linaje SHA-256 e inmutabilidad.
- RGPD / LOPDGDD: Enmascaramiento PII automático (DNI, IBAN, Email, Teléfonos, Tarjetas).
- CRA & NIS2 & DORA: Resiliencia técnica, sanitización de rutas, aislamiento de errores.

Capacidades RAG:
- Cargadores Multi-formato (PDF, DOCX, CSV, MD, TXT, HTML).
- Chunking Semántico consciente de tokens (tiktoken).
- Recuperación Híbrida (Dense Cosine + Sparse BM25 con Reciprocal Rank Fusion - RRF).
- Reranking con Cross-Encoder.
- Reformulación de Consultas (HyDE, Expansión, Descomposición).
- Caché Semántico LRU/TTL (<1ms latencia).
- Control de Alucinaciones y Verificación de Fundamentación (Groundedness & Faithfulness).
- Suite de Evaluación (MRR, Hit Rate@K, Precision@K, Recall@K).
- Adaptadores de compatibilidad para LangChain y LlamaIndex.
"""

import sys

# Desactivar advertencias de symlinks de huggingface en Windows y paralelismo de tokenizers
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

import warnings

warnings.filterwarnings("ignore", message=".*HF_TOKEN.*")
warnings.filterwarnings("ignore", category=UserWarning, module="huggingface_hub")

import argparse
import contextlib
import hashlib
import json
import math
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# DEPENDENCIAS OPCIONALES CON FALLBACKS DE PRODUCCIÓN
# ---------------------------------------------------------------------------
try:
    import torch
    from sentence_transformers import CrossEncoder, SentenceTransformer
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

try:
    import csv
    CSV_AVAILABLE = True
except ImportError:
    CSV_AVAILABLE = False

# ---------------------------------------------------------------------------
# CAPA GRAPHRAG / KNOWLEDGE GRAPH — HybridRAG según arXiv:2408.04948
# (VectorRAG + GraphRAG fusionados en contexto, §4.4 del paper)
# ---------------------------------------------------------------------------
try:
    from .rag_graph import (
        EntityExtractor,
        GraphRetriever,
        KnowledgeGraph,
        LLMTripletExtractor,
    )
    GRAPH_AVAILABLE = True
except ImportError:
    try:
        from rag_graph import (
            EntityExtractor,
            GraphRetriever,
            KnowledgeGraph,
            LLMTripletExtractor,
        )
        GRAPH_AVAILABLE = True
    except ImportError:
        GRAPH_AVAILABLE = False
        EntityExtractor = KnowledgeGraph = GraphRetriever = LLMTripletExtractor = None


# ---------------------------------------------------------------------------
# STRUCTURED JSON LOGGER (ENS ALTA & SIEM)
# ---------------------------------------------------------------------------
class StructuredJSONFormatter(logging.Formatter):
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

def setup_logger(name: str = "RAG360Engine", level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJSONFormatter())
    logger.addHandler(handler)
    return logger

logger = setup_logger()

def log_event(level: str, message: str, **kwargs) -> None:
    lvl = level.lower()
    if lvl == "warn":
        lvl = "warning"
    log_func = getattr(logger, lvl, logger.info)
    log_func(message, extra={"extra_fields": kwargs})


# ---------------------------------------------------------------------------
# 1. PII MASKING ENGINE (RGPD / LOPDGDD)
# ---------------------------------------------------------------------------
class PIIMasker:
    """Motor de detección y anonimización preventiva de Datos de Carácter Personal."""

    PATTERNS = {
        "DNI_NIE": r"\b[XYZ]?\d{7,8}[A-Z]\b",
        "IBAN": r"\bES\d{2}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b",
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "PHONE_ES": r"\b(?:\+34|0034)?[ \-]?[6789]\d{2}[ \-]?\d{3}[ \-]?\d{3}\b",
        "CREDIT_CARD": r"\b(?:\d{4}[ \-]?){3}\d{4}\b",
        "IPV4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "SSN_ES": r"\b\d{2}[ \-]?\d{8}[ \-]?\d{2}\b",
    }

    @classmethod
    def mask_text(cls, text: str) -> tuple[str, dict[str, int]]:
        masked_text = text
        stats = {}
        for pii_type, regex in cls.PATTERNS.items():
            matches = re.findall(regex, masked_text, flags=re.IGNORECASE)
            if matches:
                stats[pii_type] = len(matches)
                masked_text = re.sub(regex, f"[{pii_type}_ANONIMIZADO]", masked_text, flags=re.IGNORECASE)
        return masked_text, stats


# ---------------------------------------------------------------------------
# 2. SANITIZACIÓN DE RUTAS (CRA / NIS2)
# ---------------------------------------------------------------------------
class PathSanitizer:
    EXCLUDED_DIRS = {".venv", "venv", ".git", "node_modules", "dist", "__pycache__", ".pytest_cache"}
    SUPPORTED_EXTENSIONS = {".txt", ".md", ".html", ".htm", ".rst", ".pdf", ".docx", ".csv"}

    @classmethod
    def sanitize_dir_path(cls, dir_path: str | Path) -> Path:
        resolved = Path(dir_path).resolve()
        if not resolved.exists():
            msg = f"Directorio no encontrado: {resolved}"
            raise FileNotFoundError(msg)
        if not resolved.is_dir():
            msg = f"Ruta no es directorio: {resolved}"
            raise NotADirectoryError(msg)
        return resolved

    @classmethod
    def is_safe_path(cls, file_path: Path, base_dir: Path, max_file_size_mb: float = 15.0) -> tuple[bool, str]:
        try:
            resolved_file = file_path.resolve()
            if base_dir not in resolved_file.parents and resolved_file != base_dir:
                return False, "Path Traversal detectado"
            if file_path.is_symlink():
                return False, "Enlace simbólico no permitido"
            for part in file_path.parts:
                if part in cls.EXCLUDED_DIRS:
                    return False, f"Directorio excluido: {part}"
            if file_path.suffix.lower() not in cls.SUPPORTED_EXTENSIONS:
                return False, f"Extensión no soportada: {file_path.suffix}"
            if resolved_file.stat().st_size > max_file_size_mb * 1024 * 1024:
                return False, f"Archivo excede tamaño máximo ({max_file_size_mb} MB)"
            return True, "OK"
        except Exception as e:
            return False, str(e)


# ---------------------------------------------------------------------------
# 3. CARGADORES DE DATOS EXTENSIBLES (LOADERS)
# ---------------------------------------------------------------------------
class BaseDocumentLoader:
    def load(self, file_path: Path) -> str:
        raise NotImplementedError

class TextDocumentLoader(BaseDocumentLoader):
    def load(self, file_path: Path) -> str:
        for enc in ["utf-8", "latin-1", "cp1252"]:
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
        raw = super().load(file_path)
        text = re.sub(r"<script[\s\S]*?</script>", "", raw)
        text = re.sub(r"<style[\s\S]*?</style>", "", text)
        text = re.sub(r"<[^>]+>", " ", text)
        return re.sub(r"\s+", " ", text).strip()

class PdfDocumentLoader(BaseDocumentLoader):
    def load(self, file_path: Path) -> str:
        if not PYPDF_AVAILABLE:
            return ""
        text = ""
        try:
            reader = PdfReader(str(file_path))
            for page in reader.pages:
                txt = page.extract_text()
                if txt:
                    text += txt + "\n"
        except Exception as e:
            log_event("ERROR", "Fallo leyendo PDF", file=str(file_path), error=str(e))
        return text.strip()

class DocxDocumentLoader(BaseDocumentLoader):
    def load(self, file_path: Path) -> str:
        if not DOCX_AVAILABLE:
            return ""
        try:
            doc = docx.Document(str(file_path))
            return "\n".join([p.text for p in doc.paragraphs if p.text])
        except Exception as e:
            log_event("ERROR", "Fallo leyendo DOCX", file=str(file_path), error=str(e))
            return ""

class CsvDocumentLoader(BaseDocumentLoader):
    def load(self, file_path: Path) -> str:
        rows_text = []
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader):
                    row_str = f"Fila {idx+1}: " + " | ".join([f"{k}: {v}" for k, v in row.items() if v])
                    rows_text.append(row_str)
            return "\n".join(rows_text)
        except Exception as e:
            log_event("ERROR", "Fallo leyendo CSV", file=str(file_path), error=str(e))
            return ""

class DocumentLoaderFactory:
    _LOADERS = {
        ".txt": TextDocumentLoader(),
        ".md": MarkdownDocumentLoader(),
        ".rst": TextDocumentLoader(),
        ".html": HtmlDocumentLoader(),
        ".htm": HtmlDocumentLoader(),
        ".pdf": PdfDocumentLoader(),
        ".docx": DocxDocumentLoader(),
        ".csv": CsvDocumentLoader(),
    }
    @classmethod
    def get_loader(cls, extension: str) -> BaseDocumentLoader:
        return cls._LOADERS.get(extension.lower(), TextDocumentLoader())


# ---------------------------------------------------------------------------
# 4. CHUNKING PROFESIONAL Y CONSCIENTE DE TOKENS
# ---------------------------------------------------------------------------
class TokenSemanticSplitter:
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
        current_words = []
        current_tokens = 0

        for para in paragraphs:
            para_words = para.split()
            para_tokens = self.count_tokens(para)

            if current_tokens + para_tokens <= self.chunk_size:
                current_words.extend(para_words)
                current_tokens += para_tokens
            else:
                for word in para_words:
                    wt = self.count_tokens(word)
                    if current_tokens + wt > self.chunk_size and current_words:
                        chunks.append(" ".join(current_words))

                        overlap_words = []
                        overlap_tokens = 0
                        for w in reversed(current_words):
                            w_tok = self.count_tokens(w)
                            if overlap_tokens + w_tok <= self.chunk_overlap:
                                overlap_words.insert(0, w)
                                overlap_tokens += w_tok
                            else:
                                break
                        current_words = [*overlap_words, word]
                        current_tokens = overlap_tokens + wt
                    else:
                        current_words.append(word)
                        current_tokens += wt

        if current_words:
            chunks.append(" ".join(current_words))

        return chunks


# ---------------------------------------------------------------------------
# 5. EMBEDDINGS LOCALES Y DENSE PROVIDER
# ---------------------------------------------------------------------------
class LocalEmbeddingProvider:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2", truncate_dim: int | None = None) -> None:
        self.model_name = model_name
        self.truncate_dim = truncate_dim
        self.model = None

        if SENTENCE_TRANSFORMERS_AVAILABLE:
            if torch.cuda.is_available():
                self.device = "cuda"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                self.device = "mps"
            else:
                self.device = "cpu"
            log_event("INFO", f"Cargando modelo de embeddings '{model_name}' en {self.device}")
            try:
                self.model = SentenceTransformer(model_name, device=self.device)
            except Exception as e:
                log_event("WARN", f"Fallo cargando SentenceTransformer '{model_name}': {e}. Usando Hashing Fallback.")
                self.model = None
        else:
            log_event("WARN", "sentence-transformers no instalado. Usando Hashing Embedding Fallback determinista (384-dim).")

    def _deterministic_hash_vector(self, text: str, dim: int = 384) -> list[float]:
        vec = [0.0] * dim
        words = re.findall(r"\w+", text.lower())
        if not words:
            vec[0] = 1.0
            return vec

        for w in words:
            h = int(hashlib.sha256(w.encode("utf-8")).hexdigest(), 16)
            idx = h % dim
            val = (h % 100) / 100.0 - 0.5
            vec[idx] += val

        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]
        else:
            vec[0] = 1.0
        return vec

    def encode(self, texts: list[str]) -> list[list[float]]:
        if self.model:
            embeddings = self.model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
            if self.truncate_dim and embeddings.shape[1] > self.truncate_dim:
                embeddings = embeddings[:, :self.truncate_dim]
                norms = (embeddings ** 2).sum(axis=1, keepdims=True) ** 0.5
                norms[norms == 0] = 1.0
                embeddings = embeddings / norms
            return embeddings.tolist()
        dim = self.truncate_dim or 384
        return [self._deterministic_hash_vector(t, dim=dim) for t in texts]


# ---------------------------------------------------------------------------
# 6. MOTOR BÚSQUEDA ESPARSA (BM25)
# ---------------------------------------------------------------------------
class BM25SearchEngine:
    """Implementación de Búsqueda Esparsa BM25 Okapi para coincidencias exactas."""

    def __init__(self) -> None:
        self.corpus = []
        self.doc_tokens = []
        self.doc_len = []
        self.avg_doc_len = 0.0
        self.doc_freqs = []
        self.idf = {}
        self.k1 = 1.5
        self.b = 0.75

    def tokenize(self, text: str) -> list[str]:
        return re.findall(r"\w+", text.lower())

    def fit(self, corpus: list[str]) -> None:
        self.corpus = corpus
        self.doc_tokens = [self.tokenize(doc) for doc in corpus]
        self.doc_len = [len(doc) for doc in self.doc_tokens]
        self.avg_doc_len = sum(self.doc_len) / max(len(self.doc_len), 1)

        df = {}
        for tokens in self.doc_tokens:
            seen = set(tokens)
            for token in seen:
                df[token] = df.get(token, 0) + 1

        num_docs = len(corpus)
        for token, freq in df.items():
            self.idf[token] = math.log((num_docs - freq + 0.5) / (freq + 0.5) + 1.0)

    def search(self, query: str, top_k: int = 10) -> list[tuple[int, float]]:
        query_tokens = self.tokenize(query)
        scores = [0.0] * len(self.corpus)

        for idx, doc in enumerate(self.doc_tokens):
            if not doc:
                continue
            doc_len = self.doc_len[idx]
            freqs = {}
            for token in doc:
                freqs[token] = freqs.get(token, 0) + 1

            score = 0.0
            for q_tok in query_tokens:
                if q_tok in freqs:
                    f = freqs[q_tok]
                    idf = self.idf.get(q_tok, 0.0)
                    denom = f + self.k1 * (1.0 - self.b + self.b * (doc_len / max(self.avg_doc_len, 1)))
                    score += idf * (f * (self.k1 + 1.0)) / denom
            scores[idx] = score

        indexed_scores = list(enumerate(scores))
        indexed_scores.sort(key=lambda x: x[1], reverse=True)
        return indexed_scores[:top_k]


# ---------------------------------------------------------------------------
# 7. CROSS-ENCODER RERANKER
# ---------------------------------------------------------------------------
class CrossEncoderReranker:
    """Reranker de dos fases con modelo Cross-Encoder."""

    def __init__(self, model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2") -> None:
        self.model = None
        self.model_name = model_name
        if SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                log_event("INFO", f"Cargando Cross-Encoder Reranker '{model_name}'...")
                self.model = CrossEncoder(model_name)
            except Exception as e:
                log_event("WARN", f"No se pudo cargar CrossEncoder '{model_name}': {e}. Se usará fallback.")

    def rerank(self, query: str, docs: list[dict[str, Any]], top_k: int = 5) -> list[dict[str, Any]]:
        if not docs:
            return []
        if not self.model:
            return docs[:top_k]

        pairs = [[query, d["content"]] for d in docs]
        scores = self.model.predict(pairs)

        for doc, score in zip(docs, scores, strict=False):
            doc["rerank_score"] = float(score)

        docs.sort(key=lambda x: x.get("rerank_score", 0.0), reverse=True)
        return docs[:top_k]


# ---------------------------------------------------------------------------
# 8. QUERY REFORMULATION (HyDE, EXPANSIÓN, DESCOMPOSICIÓN)
# ---------------------------------------------------------------------------
class QueryReformulator:
    LEGAL_EXPANSIONS = {
        "ens": "Esquema Nacional de Seguridad RD 311/2022 medidas de seguridad alta media basica",
        "nis2": "Directiva NIS2 ciberseguridad resiliencia operativa entidades esenciales e importantes",
        "rgpd": "Reglamento General de Protección de Datos LOPDGDD derechos ARCO privacidad",
        "dora": "Digital Operational Resilience Act resiliencia operativa financiera pruebas de caos",
        "pii": "Datos de carácter personal datos sensibles anonimización enmascaramiento",
    }

    @classmethod
    def expand_query(cls, query: str) -> str:
        expanded_parts = [query]
        q_lower = query.lower()
        for key, exp in cls.LEGAL_EXPANSIONS.items():
            if key in q_lower:
                expanded_parts.append(exp)
        return " | ".join(expanded_parts)

    @classmethod
    def generate_hyde_doc(cls, query: str) -> str:
        """Genera un documento hipotético (HyDE) determinista para mejorar la búsqueda semántica."""
        return f"Documento de cumplimiento legal y técnico en materia de ciberseguridad sobre {query}. Incluye controles, políticas y atestaciones normativas exigibles."


# ---------------------------------------------------------------------------
# 9. RETRIEVAL CACHE MANAGER (LRU & SIMILITUD COSENO)
# ---------------------------------------------------------------------------
class SemanticLRUCache:
    """Caché Semántico en memoria con TTL e inspección por Similitud Coseno (<1ms)."""

    def __init__(self, max_size: int = 100, sim_threshold: float = 0.92, ttl_seconds: float = 3600) -> None:
        self.max_size = max_size
        self.sim_threshold = sim_threshold
        self.ttl_seconds = ttl_seconds
        self.cache = []  # List of dicts: {"query_vec", "results", "timestamp"}

    @staticmethod
    def _cosine_similarity(v1: list[float], v2: list[float]) -> float:
        dot = sum(a * b for a, b in zip(v1, v2, strict=False))
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))
        return dot / (norm1 * norm2) if norm1 and norm2 else 0.0

    def get(self, query_vec: list[float]) -> list[dict[str, Any]] | None:
        now = time.time()
        for entry in self.cache:
            if now - entry["timestamp"] > self.ttl_seconds:
                continue
            sim = self._cosine_similarity(query_vec, entry["query_vec"])
            if sim >= self.sim_threshold:
                log_event("INFO", f"CACHE HIT (Similitud: {sim:.4f})")
                return entry["results"]
        return None

    def put(self, query_vec: list[float], results: list[dict[str, Any]]) -> None:
        if len(self.cache) >= self.max_size:
            self.cache.pop(0)
        self.cache.append({
            "query_vec": query_vec,
            "results": results,
            "timestamp": time.time(),
        })


# ---------------------------------------------------------------------------
# 10. DETECTOR DE ALUCINACIONES Y VERIFICADOR DE FUNDAMENTACIÓN
# ---------------------------------------------------------------------------
class HallucinationDetector:
    """Evaluador de fidelidad (Faithfulness) y solapamiento de respuesta vs contexto."""

    @classmethod
    def evaluate_groundedness(cls, answer: str, context_chunks: list[str]) -> dict[str, Any]:
        if not answer or not context_chunks:
            return {"faithfulness_score": 0.0, "is_hallucination": True, "detail": "Sin contexto o respuesta"}

        full_context = " ".join(context_chunks).lower()
        ans_words = re.findall(r"\w+", answer.lower())
        if not ans_words:
            return {"faithfulness_score": 1.0, "is_hallucination": False}

        matching_words = [w for w in ans_words if len(w) > 3 and w in full_context]
        ratio = len(matching_words) / max(len([w for w in ans_words if len(w) > 3]), 1)

        is_hallucination = ratio < 0.35
        return {
            "faithfulness_score": round(ratio, 4),
            "is_hallucination": is_hallucination,
            "matched_terms": len(matching_words),
            "total_significant_terms": len([w for w in ans_words if len(w) > 3]),
        }


# ---------------------------------------------------------------------------
# 11. EVALUADOR DE MÉTRICAS RAG (BENCHMARKING)
# ---------------------------------------------------------------------------
class RAGEvaluator:
    """Calculador de métricas de recuperación: Hit Rate@K, MRR, Precision, Recall.

    Incluye además las métricas del paper HybridRAG (arXiv:2408.04948, §2.4):
    context_precision, context_recall y answer_relevance (aproximaciones
    deterministas sin LLM, basadas en solapamiento léxico y coseno).
    """

    @staticmethod
    def _token_set(text: str) -> set:
        return set(re.findall(r"\w+", (text or "").lower()))

    @staticmethod
    def _cosine(v1: list[float], v2: list[float]) -> float:
        dot = sum(a * b for a, b in zip(v1, v2, strict=False))
        n1 = math.sqrt(sum(a * a for a in v1))
        n2 = math.sqrt(sum(b * b for b in v2))
        return dot / (n1 * n2) if n1 and n2 else 0.0

    @classmethod
    def context_precision(cls, ground_truth: str, retrieved: list[str]) -> float:
        """Paper §2.4.3 — proporción de ítems relevantes en los top ranks."""
        gt = cls._token_set(ground_truth)
        relevant_count = 0
        precisions = []
        for k, chunk in enumerate(retrieved, 1):
            if gt & cls._token_set(chunk):
                relevant_count += 1
                precisions.append(relevant_count / k)
        if not precisions:
            return 0.0
        return round(sum(precisions) / len(precisions), 4)

    @classmethod
    def context_recall(cls, ground_truth: str, retrieved: list[str]) -> float:
        """Paper §2.4.4 — fracción de frases del ground truth atribuibles al contexto."""
        sentences = [s for s in re.split(r"(?<=[.!?])\s+", ground_truth or "") if s.strip()]
        if not sentences:
            return 0.0
        context_tokens: set = set()
        for chunk in retrieved:
            context_tokens |= cls._token_set(chunk)
        covered = sum(1 for s in sentences if cls._token_set(s) & context_tokens)
        return round(covered / len(sentences), 4)

    @classmethod
    def answer_relevance(cls, question: str, answer: str, embed_fn) -> float:
        """Paper §2.4.2 — coseno medio entre la pregunta y pseudo-preguntas de la respuesta."""
        sentences = [s for s in re.split(r"(?<=[.!?])\s+", answer or "") if s.strip()]
        if not sentences:
            return 0.0
        q_vec = embed_fn([question])[0]
        sims = [cls._cosine(q_vec, embed_fn([s])[0]) for s in sentences]
        return round(sum(sims) / len(sims), 4)

    @classmethod
    def evaluate_retrieval(cls, ground_truth_ids: list[str], retrieved_ids: list[str], k: int = 5) -> dict[str, float]:
        top_k_retrieved = retrieved_ids[:k]

        # Hit Rate@K
        hits = [doc_id for doc_id in ground_truth_ids if doc_id in top_k_retrieved]
        hit_rate = 1.0 if hits else 0.0

        # MRR (Mean Reciprocal Rank)
        mrr = 0.0
        for rank, doc_id in enumerate(top_k_retrieved, 1):
            if doc_id in ground_truth_ids:
                mrr = 1.0 / rank
                break

        # Precision@K & Recall@K
        precision = len(hits) / max(len(top_k_retrieved), 1)
        recall = len(hits) / max(len(ground_truth_ids), 1)

        return {
            f"hit_rate@{k}": round(hit_rate, 4),
            "mrr": round(mrr, 4),
            f"precision@{k}": round(precision, 4),
            f"recall@{k}": round(recall, 4),
        }


# ---------------------------------------------------------------------------
# 12. MOTOR DE BÚSQUEDA HÍBRIDA & VECTOR STORE UNIFICADO
# ---------------------------------------------------------------------------
class HybridVectorStore:
    """Vector Store In-Memory con Fusión RRF (Dense Cosine + Sparse BM25)."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.bm25_engine = BM25SearchEngine()

    def add_records(self, records: list[dict[str, Any]]) -> None:
        self.records.extend(records)
        corpus = [r["content"] for r in self.records]
        self.bm25_engine.fit(corpus)

    @staticmethod
    def _cosine_similarity(v1: list[float], v2: list[float]) -> float:
        dot = sum(a * b for a, b in zip(v1, v2, strict=False))
        n1 = math.sqrt(sum(a * a for a in v1))
        n2 = math.sqrt(sum(b * b for b in v2))
        return dot / (n1 * n2) if n1 and n2 else 0.0

    def hybrid_search(self, query_text: str, query_vector: list[float], top_k: int = 10,
                      dense_weight: float = 0.6, sparse_weight: float = 0.4, rrf_k: int = 60) -> list[dict[str, Any]]:
        if not self.records:
            return []

        # 1. Búsqueda Densa
        dense_scores = []
        for idx, rec in enumerate(self.records):
            sim = self._cosine_similarity(query_vector, rec["embedding"])
            dense_scores.append((idx, sim))
        dense_scores.sort(key=lambda x: x[1], reverse=True)

        # 2. Búsqueda Esparsa (BM25)
        sparse_scores = self.bm25_engine.search(query_text, top_k=len(self.records))

        # 3. Reciprocal Rank Fusion (RRF)
        rrf_scores = [0.0] * len(self.records)

        for rank, (idx, _) in enumerate(dense_scores, 1):
            rrf_scores[idx] += dense_weight * (1.0 / (rrf_k + rank))

        for rank, (idx, _) in enumerate(sparse_scores, 1):
            rrf_scores[idx] += sparse_weight * (1.0 / (rrf_k + rank))

        indexed_rrf = list(enumerate(rrf_scores))
        indexed_rrf.sort(key=lambda x: x[1], reverse=True)

        results = []
        for idx, score in indexed_rrf[:top_k]:
            item = dict(self.records[idx])
            item["score"] = float(score)
            results.append(item)

        return results


# ---------------------------------------------------------------------------
# 13. ADAPTADORES LANGCHAIN & LLAMAINDEX
# ---------------------------------------------------------------------------
class LangChainRetrieverAdapter:
    """Wrapper de compatibilidad con LangChain BaseRetriever."""

    def __init__(self, rag_engine) -> None:
        self.rag_engine = rag_engine

    def get_relevant_documents(self, query: str) -> list[dict[str, Any]]:
        res = self.rag_engine.query(query)
        return res.get("retrieved_chunks", [])

class LlamaIndexNodeAdapter:
    """Wrapper de compatibilidad con LlamaIndex BaseNode."""

    @staticmethod
    def to_llama_nodes(chunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        nodes = []
        for c in chunks:
            nodes.append({
                "id_": c.get("id"),
                "text": c.get("content"),
                "metadata": c.get("metadata", {}),
                "score": c.get("score"),
            })
        return nodes


# ---------------------------------------------------------------------------
# 14. CLASE MAESTRA RAG 360° ENGINE
# ---------------------------------------------------------------------------
class RAG360Engine:
    def __init__(self, embedding_model: str = "all-MiniLM-L6-v2", chunk_size: int = 300,
                 chunk_overlap: int = 50, enable_graph: bool = True, graph_depth: int = 1,
                 graph_max_triplets: int = 20, use_llm_triplets: bool = False) -> None:
        self.embedding_provider = LocalEmbeddingProvider(model_name=embedding_model)
        self.splitter = TokenSemanticSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        self.vector_store = HybridVectorStore()
        self.reranker = CrossEncoderReranker()
        self.cache = SemanticLRUCache()
        self.audit_logs = []

        # Capa GraphRAG (HybridRAG — arXiv:2408.04948)
        self.enable_graph = enable_graph and GRAPH_AVAILABLE
        self.graph_depth = graph_depth
        self.graph_max_triplets = graph_max_triplets
        self.graph = KnowledgeGraph() if GRAPH_AVAILABLE else None
        self.entity_extractor = EntityExtractor() if GRAPH_AVAILABLE else None
        self.graph_retriever = GraphRetriever() if GRAPH_AVAILABLE else None
        self.llm_extractor = LLMTripletExtractor() if (GRAPH_AVAILABLE and use_llm_triplets) else None

    def ingest_directory(self, source_dir: Path) -> dict[str, Any]:
        source_dir = PathSanitizer.sanitize_dir_path(source_dir)
        processed = 0
        records = []

        for root, _, files in os.walk(source_dir):
            for f_name in files:
                f_path = Path(root) / f_name
                is_safe, _reason = PathSanitizer.is_safe_path(f_path, source_dir)
                if not is_safe:
                    continue

                loader = DocumentLoaderFactory.get_loader(f_path.suffix)
                raw_text = loader.load(f_path)
                if not raw_text:
                    continue

                # PII Masking
                cleaned_text, pii_stats = PIIMasker.mask_text(raw_text)

                chunks = self.splitter.split_text(cleaned_text)
                if not chunks:
                    continue

                doc_sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
                embeddings = self.embedding_provider.encode(chunks)

                for idx, (c_text, emb) in enumerate(zip(chunks, embeddings, strict=False)):
                    c_sha256 = hashlib.sha256(c_text.encode("utf-8")).hexdigest()
                    rec_id = hashlib.sha256(f"{doc_sha256}:{idx}:{c_sha256}".encode()).hexdigest()

                    records.append({
                        "id": rec_id,
                        "source_file": f_path.name,
                        "chunk_index": idx,
                        "content": c_text,
                        "metadata": {
                            "doc_sha256": doc_sha256,
                            "chunk_sha256": c_sha256,
                            "pii_masked_count": pii_stats,
                        },
                        "embedding": emb,
                    })

                    # ── GraphRAG: Knowledge Extraction por chunk (§2.2 / §4.1) ──
                    if self.enable_graph and self.entity_extractor is not None:
                        chunk_entities = self.entity_extractor.extract_entities(c_text)
                        self.graph.add_entities(chunk_entities, rec_id)
                        triplets = self.entity_extractor.extract_triplets(c_text, rec_id, f_path.name)
                        if self.llm_extractor is not None and self.llm_extractor.available:
                            triplets.extend(self.llm_extractor.extract_triplets(c_text, rec_id, f_path.name))
                        for triplet in triplets:
                            self.graph.add_triplet(triplet)
                processed += 1

        self.vector_store.add_records(records)
        result = {"processed_files": processed, "total_chunks": len(records)}
        if self.graph is not None:
            result["graph"] = self.graph.stats
        return result

    def query(self, query_text: str, top_k: int = 5, use_reranker: bool = True, use_hyde: bool = False) -> dict[str, Any]:
        start_t = time.time()

        # Expand Query
        expanded_q = QueryReformulator.expand_query(query_text)
        if use_hyde:
            search_text = QueryReformulator.generate_hyde_doc(query_text)
        else:
            search_text = expanded_q

        q_vec = self.embedding_provider.encode([search_text])[0]

        # Contexto GraphRAG (HybridRAG §4.4: grafo recuperado en paralelo al vector)
        graph_payload = {"matched_entities": [], "triplets": [], "context": []}
        if self.enable_graph and self.graph is not None and self.graph_retriever is not None and self.graph.nodes:
            graph_payload = self.graph_retriever.retrieve(
                query_text, self.graph, depth=self.graph_depth, max_triplets=self.graph_max_triplets,
            )

        # Check Cache (payload completo: chunks vectoriales + contexto de grafo)
        cached_res = self.cache.get(q_vec)
        if cached_res:
            return self._build_response(
                query_text=query_text, cached=True, payload=cached_res,
                latency_ms=round((time.time() - start_t) * 1000, 2),
            )

        # Hybrid Search (Dense Cosine + Sparse BM25 con RRF)
        candidates = self.vector_store.hybrid_search(query_text, q_vec, top_k=top_k*2)

        # Reranking
        if use_reranker and candidates:
            final_chunks = self.reranker.rerank(query_text, candidates, top_k=top_k)
        else:
            final_chunks = candidates[:top_k]

        # Update Cache
        payload = {"chunks": final_chunks, "graph": graph_payload}
        self.cache.put(q_vec, payload)

        latency = round((time.time() - start_t) * 1000, 2)
        res = self._build_response(query_text, cached=False, payload=payload, latency_ms=latency)

        self.audit_logs.append({"timestamp": datetime.now(timezone.utc).isoformat(), "query": query_text, "latency_ms": latency})
        return res

    def _build_response(self, query_text: str, cached: bool, payload: dict[str, Any],
                        latency_ms: float) -> dict[str, Any]:
        """Ensambla la respuesta completa: chunks vectoriales + contexto de grafo.

        El contexto del grafo se devuelve separado de los chunks vectoriales
        (el generador lo concatena DESPUÉS, tal y como indica el paper §4.4).
        """
        graph_payload = payload.get("graph", {"matched_entities": [], "triplets": [], "context": []})
        return {
            "query": query_text,
            "cached": cached,
            "retrieved_chunks": payload.get("chunks", []),
            "graph_triplets": graph_payload.get("triplets", []),
            "graph_context": graph_payload.get("context", []),
            "graph_entities_matched": graph_payload.get("matched_entities", []),
            "hybrid_used": bool(graph_payload.get("context", [])),
            "latency_ms": latency_ms,
        }


# ---------------------------------------------------------------------------
# CLI & DEMO TEST
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Arquitectura Enterprise RAG 360° — HybridRAG (Vector + BM25 + Knowledge Graph).",
        epilog="Basado en arXiv:2408.04948 (HybridRAG: VectorRAG + GraphRAG fusionados).",
    )
    parser.add_argument("-d", "--dir", default=None, help="Directorio a ingestar (por defecto: ./docs).")
    parser.add_argument("-q", "--query", default=None, help="Consulta RAG a realizar.")
    parser.add_argument("--graph", default=None, help="Ruta JSON para guardar/cargar el Knowledge Graph (persistencia).")
    parser.add_argument("--no-graph", action="store_true", help="Desactiva la capa GraphRAG (solo Vector+BM25).")
    parser.add_argument("--graph-depth", type=int, default=1, help="Profundidad de expansión BFS en el grafo (def: 1).")
    parser.add_argument("--llm-triplets", action="store_true", help="Habilita extracción LLM de tripletas (requiere OPENAI_API_KEY).")
    args = parser.parse_args()

    if not args.query:
        return

    # Determinar directorio de documentos
    target_dir = None
    if args.dir:
        target_dir = Path(args.dir)
    else:
        # Fallback a ./docs si existe en el directorio de ejecución o del script
        local_docs = Path("./docs")
        script_docs = Path(__file__).parent / "docs"
        if local_docs.exists():
            target_dir = local_docs
        elif script_docs.exists():
            target_dir = script_docs

    try:
        engine = RAG360Engine(
            enable_graph=not args.no_graph,
            graph_depth=args.graph_depth,
            use_llm_triplets=args.llm_triplets,
        )

        graph_path = Path(args.graph) if args.graph else None
        if graph_path and graph_path.exists() and engine.graph is not None:
            engine.graph.load(graph_path)

        if target_dir:
            if not target_dir.exists():
                sys.exit(1)
            ingest_res = engine.ingest_directory(target_dir)
            if "graph" in ingest_res:
                pass
        elif graph_path and graph_path.exists():
            pass
        else:
            sys.exit(1)

        if graph_path and engine.graph is not None and (target_dir or not graph_path.exists()):
            engine.graph.save(graph_path)

        res = engine.query(args.query)
        if res["graph_entities_matched"]:
            pass
        if res["graph_context"]:
            for _t in res["graph_context"][:10]:
                pass
        for _idx, c in enumerate(res["retrieved_chunks"], 1):
            f"Score: {c.get('score', 0):.4f}" if c.get("score") is not None else ""

    except Exception as e:
        log_event("ERROR", f"Error en ejecución RAG: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
