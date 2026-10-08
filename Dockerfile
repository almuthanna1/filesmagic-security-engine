FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

WORKDIR /srv

# Runtime dependencies only; test tooling lives in requirements-dev.txt.
COPY requirements.txt .
RUN pip install -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin engine

COPY app ./app

USER engine
EXPOSE 8000

# Render injects PORT (default 10000); 8000 is the local fallback. No --reload in production.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port \"$PORT\""]
