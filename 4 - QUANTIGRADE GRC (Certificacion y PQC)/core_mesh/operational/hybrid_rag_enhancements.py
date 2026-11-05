"""Quantigrade GCR - Hybrid RAG Enhancements Module.

Implements Enterprise Retrieval Augmentation with:
- BM25 Okapi Lexical Search Engine (exact article/law lookup)
- Reciprocal Rank Fusion (RRF k=60, dense + sparse fusion)
- Dual-Mode Semantic LRU Cache (In-Memory stdlib default + optional Redis adapter)
Aligned with DORA Art. 6, ENS Alta, and EU AI Act Art. 15.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from collections import Counter, OrderedDict
from typing import Any, Dict, List, Optional, Tuple

try:
    from rank_bm25 import BM25Okapi
    HAS_RANK_BM25 = True
except ImportError:
    HAS_RANK_BM25 = False

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False


def tokenize(text: str) -> List[str]:
    """Tokenize and normalize text into lowercase alphanumeric tokens."""
    return re.findall(r"\b[a-zA-Z0-9_\-\.]{2,}\b", text.lower())


def compute_tf_idf_vector(tokens: List[str], idf_dict: Dict[str, float]) -> Dict[str, float]:
    """Calculate normalized TF-IDF vector for a list of tokens."""
    counts = Counter(tokens)
    total = len(tokens) or 1
    vec: Dict[str, float] = {}
    norm_sq = 0.0
    for term, cnt in counts.items():
        tf = cnt / total
        idf = idf_dict.get(term, 1.0)
        weight = tf * idf
        vec[term] = weight
        norm_sq += weight * weight
    norm = math.sqrt(norm_sq) or 1.0
    return {k: v / norm for k, v in vec.items()}


def cosine_similarity(vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
    """Calculate cosine similarity between two sparse normalized vectors."""
    if not vec_a or not vec_b:
        return 0.0
    # Iterate over the smaller vector
    if len(vec_a) > len(vec_b):
        vec_a, vec_b = vec_b, vec_a
    score = 0.0
    for k, v in vec_a.items():
        if k in vec_b:
            score += v * vec_b[k]
    return max(0.0, min(1.0, score))


class BM25SearchEngine:
    """BM25 Okapi lexical retrieval engine for exact articles, regulations, and codes."""

    def __init__(self, corpus: Optional[List[Dict[str, Any]]] = None) -> None:
        self.corpus: List[Dict[str, Any]] = []
        self.tokenized_corpus: List[List[str]] = []
        self.bm25: Optional[Any] = None
        self.idf_dict: Dict[str, float] = {}
        if corpus:
            self.index(corpus)

    def index(self, corpus: List[Dict[str, Any]]) -> None:
        """Index a corpus of documents: each doc is expected to have 'id' and 'content'."""
        self.corpus = corpus
        self.tokenized_corpus = [tokenize(doc.get("content", "")) for doc in corpus]
        if HAS_RANK_BM25 and self.tokenized_corpus:
            self.bm25 = BM25Okapi(self.tokenized_corpus)
        else:
            self.bm25 = None
            self._compute_manual_idf()

    def _compute_manual_idf(self) -> None:
        """Fallback IDF calculation for pure stdlib Okapi scoring."""
        num_docs = len(self.tokenized_corpus)
        df: Counter[str] = Counter()
        for doc in self.tokenized_corpus:
            df.update(set(doc))
        self.idf_dict = {
            term: math.log(1.0 + (num_docs - count + 0.5) / (count + 0.5))
            for term, count in df.items()
        }

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search query against indexed corpus, returning ranked documents."""
        if not self.corpus:
            return []
        tokens = tokenize(query)
        if not tokens:
            return []

        if HAS_RANK_BM25 and self.bm25 is not None:
            scores = self.bm25.get_scores(tokens)
            ranked_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:top_k]
            results = []
            for idx in ranked_indices:
                score = float(scores[idx])
                if score <= 0.0:
                    continue
                doc = dict(self.corpus[idx])
                doc["bm25_score"] = round(score, 4)
                results.append(doc)
            return results

        # Fallback scoring
        scores_list = []
        for idx, doc_tokens in enumerate(self.tokenized_corpus):
            doc_cnt = Counter(doc_tokens)
            doc_len = len(doc_tokens) or 1
            avg_len = sum(len(d) for d in self.tokenized_corpus) / (len(self.tokenized_corpus) or 1)
            score = 0.0
            k1, b = 1.5, 0.75
            for term in tokens:
                if term in doc_cnt:
                    freq = doc_cnt[term]
                    idf = self.idf_dict.get(term, 1.0)
                    denom = freq + k1 * (1.0 - b + b * (doc_len / avg_len))
                    score += idf * (freq * (k1 + 1.0)) / (denom or 1.0)
            if score > 0.0:
                scores_list.append((idx, score))

        scores_list.sort(key=lambda x: x[1], reverse=True)
        results = []
        for idx, score in scores_list[:top_k]:
            doc = dict(self.corpus[idx])
            doc["bm25_score"] = round(score, 4)
            results.append(doc)
        return results


class ReciprocalRankFuser:
    """Reciprocal Rank Fusion (RRF) for combining Dense and Sparse (BM25) search results."""

    def __init__(self, k: int = 60, dense_weight: float = 0.6, sparse_weight: float = 0.4) -> None:
        self.k = k
        self.dense_weight = dense_weight
        self.sparse_weight = sparse_weight

    def fuse(
        self,
        dense_results: List[Dict[str, Any]],
        sparse_results: List[Dict[str, Any]],
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Combine dense and sparse lists using weighted RRF formula."""
        doc_map: Dict[str, Dict[str, Any]] = {}
        rrf_scores: Dict[str, float] = {}

        # Dense pass
        for rank, item in enumerate(dense_results, start=1):
            doc_id = str(item.get("id", item.get("doc_id", f"dense_{rank}")))
            doc_map[doc_id] = item
            score = self.dense_weight / (self.k + rank)
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0.0) + score

        # Sparse pass
        for rank, item in enumerate(sparse_results, start=1):
            doc_id = str(item.get("id", item.get("doc_id", f"sparse_{rank}")))
            if doc_id not in doc_map:
                doc_map[doc_id] = item
            score = self.sparse_weight / (self.k + rank)
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0.0) + score

        # Rank by final fused score
        sorted_ids = sorted(rrf_scores.keys(), key=lambda d: rrf_scores[d], reverse=True)[:top_k]
        output = []
        for doc_id in sorted_ids:
            doc = dict(doc_map[doc_id])
            doc["rrf_score"] = round(rrf_scores[doc_id], 6)
            output.append(doc)
        return output


class SemanticLRUCache:
    """Dual-Mode Semantic LRU Cache.
    
    Operates in 100% In-Memory Native mode by default.
    If redis_url is provided and reachable, delegates persistence/TTL to Redis while maintaining
    semantic cosine matching for queries.
    """

    def __init__(
        self,
        capacity: int = 500,
        similarity_threshold: float = 0.92,
        redis_url: Optional[str] = None,
        use_redis: bool = False,
    ) -> None:
        self.capacity = capacity
        self.similarity_threshold = similarity_threshold
        self.use_redis = use_redis or bool(os.getenv("REDIS_URL") or redis_url)
        self.redis_client: Optional[Any] = None
        self._memory_cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self.hits = 0
        self.misses = 0

        if self.use_redis and HAS_REDIS:
            target_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
            try:
                client = redis.from_url(target_url, decode_responses=True, socket_timeout=1.0)
                client.ping()
                self.redis_client = client
            except Exception:
                # Graceful fallback to in-memory mode without raising fatal errors
                self.redis_client = None

    def _get_vector(self, query: str) -> Dict[str, float]:
        tokens = tokenize(query)
        cnt = Counter(tokens)
        total = len(tokens) or 1
        sq = sum((c / total) ** 2 for c in cnt.values())
        norm = math.sqrt(sq) or 1.0
        return {k: (v / total) / norm for k, v in cnt.items()}

    def get(self, query: str, threshold: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Lookup response by exact match or semantic similarity >= threshold."""
        min_thresh = threshold or self.similarity_threshold
        query_vec = self._get_vector(query)
        now = time.time()

        # Check exact hit in Redis first if active
        if self.redis_client:
            try:
                exact_key = f"qg_cache:exact:{hashlib.sha256(query.strip().lower().encode()).hexdigest()}"
                cached_json = self.redis_client.get(exact_key)
                if cached_json:
                    self.hits += 1
                    return json.loads(cached_json)
            except Exception:
                pass

        # Check memory cache (exact or semantic similarity)
        best_match: Optional[Tuple[str, float, Dict[str, Any]]] = None
        expired_keys: List[str] = []

        for key, entry in self._memory_cache.items():
            if entry["expires_at"] <= now:
                expired_keys.append(key)
                continue
            sim = cosine_similarity(query_vec, entry["vector"])
            if sim >= min_thresh and (best_match is None or sim > best_match[1]):
                best_match = (key, sim, entry["response"])

        for exp_k in expired_keys:
            self._memory_cache.pop(exp_k, None)

        if best_match:
            matched_key, sim_score, resp = best_match
            self._memory_cache.move_to_end(matched_key)
            self.hits += 1
            result = dict(resp)
            result["cache_hit"] = True
            result["semantic_similarity"] = round(sim_score, 4)
            return result

        self.misses += 1
        return None

    def put(self, query: str, response: Dict[str, Any], ttl_s: int = 3600) -> None:
        """Store query and response in cache with TTL."""
        query_vec = self._get_vector(query)
        key = hashlib.sha256(query.strip().lower().encode()).hexdigest()
        expires_at = time.time() + ttl_s

        # Store in Redis if connected
        if self.redis_client:
            try:
                exact_key = f"qg_cache:exact:{key}"
                self.redis_client.setex(exact_key, ttl_s, json.dumps(response))
            except Exception:
                pass

        # Evict oldest if capacity exceeded
        if len(self._memory_cache) >= self.capacity:
            self._memory_cache.popitem(last=False)

        self._memory_cache[key] = {
            "query": query,
            "vector": query_vec,
            "response": response,
            "expires_at": expires_at,
        }

    def clear(self) -> None:
        """Clear all cached entries."""
        self._memory_cache.clear()
        if self.redis_client:
            try:
                keys = self.redis_client.keys("qg_cache:*")
                if keys:
                    self.redis_client.delete(*keys)
            except Exception:
                pass
        self.hits = 0
        self.misses = 0

    def stats(self) -> Dict[str, Any]:
        """Return cache performance statistics."""
        total = self.hits + self.misses
        hit_ratio = round(self.hits / total, 4) if total > 0 else 0.0
        return {
            "capacity": self.capacity,
            "cached_items": len(self._memory_cache),
            "hits": self.hits,
            "misses": self.misses,
            "hit_ratio": hit_ratio,
            "backend": "redis" if self.redis_client else "native_memory",
        }

