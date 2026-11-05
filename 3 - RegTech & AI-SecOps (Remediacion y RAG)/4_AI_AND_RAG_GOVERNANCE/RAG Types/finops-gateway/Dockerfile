FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY ["RAG Types/finops-gateway/requirements.txt", "/app/requirements.txt"]
RUN pip install --no-cache-dir -r /app/requirements.txt || pip install --no-cache-dir fastapi uvicorn pydantic

COPY ["RAG Types/finops-gateway/", "/app/"]
COPY ["shared-telemetry/", "/app/shared-telemetry/"]

EXPOSE 8000

CMD ["uvicorn", "gateway_api:app", "--host", "0.0.0.0", "--port", "8000"]
