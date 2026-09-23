# syntax=docker/dockerfile:1

# ---------- Stage 1: build the React/TypeScript frontend ----------
FROM node:22-bookworm-slim AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: FastAPI runtime, also serves the built SPA ----------
FROM python:3.11-slim AS backend
ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    STATIC_DIR=/app/frontend/dist
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY --from=frontend /frontend/dist /app/frontend/dist
RUN mkdir -p /data
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=10 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ---------- Stage 3: one-shot verification (tests + frontend build + smoke) ----------
FROM node:22-bookworm AS verify
ENV PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    BASE_URL=http://web:8000
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
WORKDIR /app/verify
COPY verify/ ./
CMD ["bash", "/app/verify/run.sh"]
