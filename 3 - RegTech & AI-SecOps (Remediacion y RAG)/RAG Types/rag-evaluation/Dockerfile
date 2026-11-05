FROM python:3.13-slim

WORKDIR /app

COPY ["RAG Types/rag-evaluation/requirements.txt", "/app/requirements.txt"]
RUN pip install --no-cache-dir -r /app/requirements.txt || pip install --no-cache-dir pytest pydantic

COPY ["RAG Types/rag-evaluation/", "/app/"]
COPY ["shared-telemetry/", "/app/shared-telemetry/"]

CMD ["python", "evaluate_rag.py"]
