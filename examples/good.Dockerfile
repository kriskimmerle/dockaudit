# Example: A well-written Dockerfile
FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /app /app

RUN groupadd -r appuser && useradd -r -g appuser appuser

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["curl", "-f", "http://localhost:8080/health"] || exit 1

ENTRYPOINT ["python3", "-m", "gunicorn"]
CMD ["--bind", "0.0.0.0:8080", "app:app"]
