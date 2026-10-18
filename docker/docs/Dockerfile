# The documentation site: built with MkDocs, served by nginx at /docs/.
#
#   docker build -t turkeybite-docs -f docker/docs/Dockerfile .
#
# Built from the repository root, since a few pages are made from the code
# and the example files (see docker/docs/hooks.py). It is meant to run beside
# the console, which serves it at /docs/ to people who are signed in, and
# publishes no port of its own.

# Base images are pinned by digest, so a rebuild uses the same bytes; update
# the digests deliberately, with the tag beside them saying what they are
FROM python:3.13-slim@sha256:3dd7cc108ec1493442514f5c2a871af6af0ec31d768ff6e378a93340c3b3db5f AS build
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NO_MKDOCS_2_WARNING=true TBDOCS_SITE_URL=http://localhost/docs/
WORKDIR /src
COPY docker/docs/requirements.txt docker/docs/requirements.txt
RUN pip install --require-hashes -r docker/docs/requirements.txt
# Only what the site is made from
COPY mkdocs.yml ./
COPY docker/docs/hooks.py docker/docs/hooks.py
COPY docs docs
COPY console/docs/screenshots console/docs/screenshots
COPY console/console.env.example console/console.env.example
COPY console/backend/tbconsole/analysis/defaults.py console/backend/tbconsole/analysis/defaults.py
COPY console/backend/tbconsole/__main__.py console/backend/tbconsole/__main__.py
COPY src/libtb/taxonomy src/libtb/taxonomy
COPY src/support/config.example.yaml src/support/config.example.yaml
COPY src/turkeybite src/turkeybite
COPY vols/lists/host_files.example.json vols/lists/host_files.example.json
RUN mkdocs build --strict --site-dir /site

FROM nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6
COPY docker/docs/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /site /usr/share/nginx/html/docs
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
