# OWASP LLM & Pre-RAG Guardrail Evidence Report

- **Timestamp:** 2026-07-26T10:30:31.114126+00:00
- **Mode:** `enforce`
- **Is Safe:** `False`
- **Risk Score:** `0.75`
- **SHA-256 Checksum:** `6da432d222d8ec1f45a8b79505bc1375a81b9a2bec0977bb210848bbcae9dc35`

## Flags & Detections
```json
[
  "Removed system prompt override pattern: System\\s*:\\s*",
  "Removed system prompt override pattern: forget\\s+all\\s+rules",
  "Redacted 1 instances of EMAIL"
]
```

## Sanitized Prompt (Vector DB Ready)
```text
[REMOVED_SYSTEM_INSTRUCTION][REMOVED_SYSTEM_INSTRUCTION] and email [ANONYMIZED_EMAIL]
```
