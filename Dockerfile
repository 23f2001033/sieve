# Single-instance by design. Every correctness guarantee in this project — the
# idempotency UNIQUE constraint as the sole serialisation point, the in-process
# budget lock, the single-writer hash chain — assumes exactly one process against
# one disk. Scale this horizontally and those guarantees break; see docs/LIMITS.md.
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

COPY pyproject.toml README.md ./
COPY sieve ./sieve
RUN pip install --no-cache-dir -e .

COPY ui ./ui
COPY scripts ./scripts

# Binds $PORT when the host injects one (Render), else 7860 (the Hugging Face
# Spaces default). One image serves both.
EXPOSE 7860
CMD ["sh", "-c", "uvicorn sieve.gateway.api:app --host 0.0.0.0 --port ${PORT:-7860}"]
