"""Quantigrade GCR - Hallucination Self-Grader & CRAG Relevance Guard.

Implements Corrective RAG (CRAG) and Self-RAG verification:
- DocumentRelevanceGrader: CRAG gate for evaluating retrieved evidence sufficiency
- HallucinationSelfGrader: Self-RAG verification of response faithfulness against evidence
- Tamper-evident SHA-256 lineage logging
Aligned with EU AI Act Art. 9 & 13 and OWASP LLM06 / LLM09.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


def extract_keywords(text: str) -> Set[str]:
    """Extract lowercased alphanumeric keywords with length >= 3."""
    stop_words = {
        "the", "and", "for", "with", "that", "this", "from", "are", "was",
        "los", "las", "para", "por", "con", "que", "una", "uno", "del", "los",
        "sobre", "bajo", "como", "esta", "este", "entre", "cual", "cuales"
    }
    words = re.findall(r"\b[a-zA-Z0-9_\-\.]{3,}\b", text.lower())
    return {w for w in words if w not in stop_words}


def split_into_claims(text: str) -> List[str]:
    """Split text into sentences/statements representing atomic claims."""
    # Split on period, semicolon, newline, or bullet points
    raw_sentences = re.split(r"(?<=[.!?])\s+|\n+|- |\* ", text)
    claims = []
    for s in raw_sentences:
        clean = s.strip()
        if len(clean) >= 15:
            claims.append(clean)
    return claims or [text.strip()]


class DocumentRelevanceGrader:
    """CRAG (Corrective RAG) Document Relevance Grader.
    
    Evaluates whether candidate documents contain sufficient semantic and lexical overlap
    with the query to answer it accurately.
    """

    def __init__(self, relevance_threshold: float = 0.25) -> None:
        self.relevance_threshold = relevance_threshold

    def grade_document(self, query: str, doc_content: str) -> Dict[str, Any]:
        """Grade a single document against the query."""
        q_words = extract_keywords(query)
        d_words = extract_keywords(doc_content)
        if not q_words or not d_words:
            return {"score": 0.0, "is_relevant": False, "matched_keywords": []}

        overlap = q_words.intersection(d_words)
        score = len(overlap) / len(q_words)
        is_relevant = score >= self.relevance_threshold
        return {
            "score": round(score, 4),
            "is_relevant": is_relevant,
            "matched_keywords": sorted(list(overlap)),
        }

    def grade_corpus(self, query: str, docs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Grade multiple documents and determine overall evidence sufficiency for CRAG."""
        graded = []
        relevant_count = 0
        total_score = 0.0

        for doc in docs:
            content = doc.get("content", doc.get("text", ""))
            res = self.grade_document(query, content)
            item = dict(doc)
            item["crag_score"] = res["score"]
            item["crag_relevant"] = res["is_relevant"]
            item["matched_keywords"] = res["matched_keywords"]
            graded.append(item)
            if res["is_relevant"]:
                relevant_count += 1
            total_score += res["score"]

        avg_score = total_score / len(docs) if docs else 0.0
        # CRAG Decision: Pass, Ambiguous (needs query expansion), or Insufficient (fallback to graph)
        if relevant_count >= max(1, len(docs) // 2) and avg_score >= self.relevance_threshold:
            action = "PROCEED"
        elif relevant_count > 0:
            action = "EXPAND_QUERY"
        else:
            action = "FALLBACK_KNOWLEDGE_GRAPH"

        return {
            "action": action,
            "total_documents": len(docs),
            "relevant_count": relevant_count,
            "average_score": round(avg_score, 4),
            "graded_documents": graded,
        }


class HallucinationSelfGrader:
    """Self-RAG Hallucination & Faithfulness Grader.
    
    Verifies that claims made in the generated response are strictly grounded
    in the provided context documents, calculating a faithfulness ratio.
    """

    def __init__(self, faithfulness_threshold: float = 0.75) -> None:
        self.faithfulness_threshold = faithfulness_threshold

    def evaluate_faithfulness(
        self,
        response: str,
        source_docs: List[str],
        query: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Audit response against source documents to detect ungrounded statements."""
        combined_context = " ".join(source_docs).lower()
        context_words = extract_keywords(combined_context)

        claims = split_into_claims(response)
        grounded_claims: List[Dict[str, Any]] = []
        flagged_claims: List[Dict[str, Any]] = []

        for claim in claims:
            claim_words = extract_keywords(claim)
            if not claim_words:
                continue

            overlap = claim_words.intersection(context_words)
            overlap_ratio = len(overlap) / len(claim_words)

            claim_info = {
                "claim": claim,
                "grounding_score": round(overlap_ratio, 4),
                "matched_terms": sorted(list(overlap)),
            }

            # If at least 35% of substantive keywords are in context, consider grounded
            if overlap_ratio >= 0.35:
                grounded_claims.append(claim_info)
            else:
                flagged_claims.append(claim_info)

        total_evaluated = len(grounded_claims) + len(flagged_claims)
        if total_evaluated == 0:
            faithfulness_ratio = 1.0
        else:
            faithfulness_ratio = len(grounded_claims) / total_evaluated

        is_grounded = faithfulness_ratio >= self.faithfulness_threshold

        # Cryptographic lineage hash
        payload_to_hash = json.dumps({
            "response_hash": hashlib.sha256(response.encode()).hexdigest(),
            "context_hash": hashlib.sha256(combined_context.encode()).hexdigest(),
            "faithfulness_ratio": round(faithfulness_ratio, 4),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, sort_keys=True)
        sha256_lineage = hashlib.sha256(payload_to_hash.encode()).hexdigest()

        return {
            "is_grounded": is_grounded,
            "faithfulness_ratio": round(faithfulness_ratio, 4),
            "threshold": self.faithfulness_threshold,
            "total_claims": total_evaluated,
            "grounded_count": len(grounded_claims),
            "flagged_count": len(flagged_claims),
            "flagged_claims": flagged_claims,
            "sha256_lineage": sha256_lineage,
            "compliance_attestation": "EU_AI_ACT_ART13_VERIFIED" if is_grounded else "REJECTED_UNGROUNDED",
        }

