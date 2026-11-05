FROM python:3.11-alpine

# Security hardening: no root
RUN adduser -D bunkeruser

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Adjust permissions
RUN chown -R bunkeruser:bunkeruser /app

USER bunkeruser

CMD ["python", "-m", "pytest"]
