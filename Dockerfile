FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TRIAGE_ROOT=/app

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN pip install .

COPY public ./public
COPY reports/w3_traces.json ./reports/w3_traces.json

EXPOSE 8000

CMD ["uvicorn", "triage.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
