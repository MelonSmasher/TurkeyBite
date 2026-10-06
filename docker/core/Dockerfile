FROM python:3.14-alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

WORKDIR /turkey-bite

ENV TZ=America/New_York
# Supervisor sends each program's stdout to a file, and Python buffers when
# stdout is not a tty, so periodic progress output sat unflushed until 8 KB
# had accumulated. That defeats the point of a status line.
ENV PYTHONUNBUFFERED=1
ENV TB_ROLE=core

COPY docker/core/run-core.sh ./run.sh
COPY src/libtb ./libtb
COPY src/turkeybite .
COPY src/requirements.txt .

RUN pip3 install --no-cache --upgrade pip setuptools wheel && \
    pip3 install -r requirements.txt && \
    apk add --no-cache envsubst && \
    chmod +x run.sh && \
    mkdir -p /var/log/turkey-bite


VOLUME ["/var/log/turkey-bite", "/turkey-bite/lists", "/turkey-bite/config.yaml"]

ENTRYPOINT ["./run.sh"]