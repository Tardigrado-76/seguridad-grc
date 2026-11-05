FROM python:3.11-alpine
RUN apk add --no-cache gcc musl-dev libffi-dev build-base
RUN adduser -D bunkeruser
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chown -R bunkeruser:bunkeruser /app
USER bunkeruser
CMD ["python", "-m", "pytest", "-q"]
