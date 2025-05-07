FROM python:3-alpine

WORKDIR /turkey-bite

ENV TZ=America/New_York
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