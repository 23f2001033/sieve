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

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "sieve.gateway.api:app", "--host", "0.0.0.0", "--port", "8000"]
