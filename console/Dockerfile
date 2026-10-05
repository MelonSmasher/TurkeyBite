# The TurkeyBite Console: the app built with Node, served by the API in Python.
#
#   docker build -t turkeybite-console console/
#
# The image runs as an unprivileged user and holds no secrets; everything is
# configured through TBCONSOLE_* variables, see console.env.example.

# Base images are pinned by digest, so a rebuild uses the same bytes; update
# the digests deliberately, with the tag beside them saying what they are
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS app
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npx vite build --outDir /dist --emptyOutDir

FROM python:3.13-slim@sha256:3dd7cc108ec1493442514f5c2a871af6af0ec31d768ff6e378a93340c3b3db5f
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin tbconsole
WORKDIR /app
COPY backend/requirements.txt backend/requirements.lock ./
RUN pip install -r requirements.txt -c requirements.lock
COPY backend/alembic.ini ./
COPY backend/tbconsole ./tbconsole
# The demo writes made-up events and empties databases; it has no place in
# an image meant for a real deployment
RUN rm -f tbconsole/demo.py
COPY --from=app /dist ./tbconsole/static
USER tbconsole
EXPOSE 8710
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8710/healthz', timeout=4)"
# Migrates the schema, then serves. Several replicas can start at once:
# migrations and the built-in rule sync take a Postgres advisory lock in turn,
# and the background work is claimed with SKIP LOCKED or a lease.
CMD ["python", "-m", "tbconsole", "serve", "--migrate"]
