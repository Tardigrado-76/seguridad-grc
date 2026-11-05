FROM python:3.13-slim

WORKDIR /app

COPY ["workflow-automation/event-driven-auditor/requirements.txt", "/app/requirements.txt"]
RUN pip install --no-cache-dir -r /app/requirements.txt || pip install --no-cache-dir redis pydantic

COPY ["workflow-automation/event-driven-auditor/", "/app/"]

CMD ["python", "consumer.py"]
