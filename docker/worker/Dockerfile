FROM python:3-alpine

ENV TZ=America/New_York
ENV TB_ROLE=worker

WORKDIR /turkey-bite

COPY docker/worker/run-worker.sh ./run.sh
COPY src/libtb ./libtb
COPY src/turkeybite .
COPY src/requirements.txt .


RUN pip3 install --no-cache --upgrade pip setuptools wheel && \
    pip3 install -r requirements.txt && \
    apk add --no-cache supervisor envsubst && \
    chmod +x run.sh && \
    mkdir -p /var/log/turkey-bite && \
    rm -rf /etc/supervisor && \
    mkdir /etc/supervisor

COPY src/supervisor /etc/supervisor

RUN chmod 644 /etc/supervisor/supervisord.conf /etc/supervisor/conf.d/*.template && \
    chmod 755 /etc/supervisor /etc/supervisor/conf.d && \
    chown -R root:root /etc/supervisor

VOLUME ["/var/log/turkey-bite", "/turkey-bite/lists", "/turkey-bite/config.yaml"]

ENTRYPOINT ["./run.sh"]