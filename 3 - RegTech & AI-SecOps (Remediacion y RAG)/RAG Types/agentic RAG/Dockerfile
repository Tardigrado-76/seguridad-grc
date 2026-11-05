FROM python:3.11-slim
RUN useradd -m bunkeruser
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chown -R bunkeruser:bunkeruser /app
USER bunkeruser
CMD ["python", "-m", "pytest", "-q"]
