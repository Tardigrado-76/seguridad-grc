# QUANTIGRADE GCR — Executive Cockpit & Zero-Trust Console

## Architecture Overview

QUANTIGRADE GCR Console provides a unified Zero-Trust operations cockpit for automated GCR orchestration:
1. **Headless Execution Engine (`core_mesh/operational/headless_gcr_api.py`)**: Lightweight, high-throughput microservice for CI/CD pipelines (GitHub Actions, GitLab CI, Azure DevOps) with HMAC-SHA256 signed webhooks.
2. **Interactive Management Console (`console/backend/`)**: FastAPI backend featuring Zero-Trust script whitelisting, logical client tenant isolation, and real-time Server-Sent Events (SSE) telemetry streaming.
3. **Frontend Dashboard (`console/frontend/`)**: Modern Next.js interface providing real-time log observation, posture scorecards, and human-in-the-loop (HITL) approval gates.

## Zero-Docker Architecture
- All components operate in native Python / PowerShell / Bash environments.
- Zero dependency on Docker daemon or virtualization containers.

