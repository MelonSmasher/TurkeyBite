# The TurkeyBite Console: the app built with Node, served by the API in Python.
#
#   docker build -t turkeybite-console console/
#
# The image runs as an unprivileged user and holds no secrets; everything is
# configured through TBCONSOLE_* variables, see console.env.example.

FROM node:24-alpine AS app
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npx vite build --outDir /dist --emptyOutDir

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin tbconsole
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install -r requirements.txt
COPY backend/alembic.ini ./
COPY backend/tbconsole ./tbconsole
COPY --from=app /dist ./tbconsole/static
USER tbconsole
EXPOSE 8710
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8710/healthz', timeout=4)"
# Migrates the schema, then serves. Several replicas can start at once:
# Alembic serialises on its version table, and the background work is claimed
# with SKIP LOCKED.
CMD ["python", "-m", "tbconsole", "serve", "--migrate"]
