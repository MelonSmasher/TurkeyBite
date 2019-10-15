FROM alpine:latest

WORKDIR /turkeybite

COPY . .

ENV ROLE "worker"

RUN apk --no-cache --update add python3 sed supervisor vim dos2unix && \
    pip3 install --no-cache --upgrade pip setuptools wheel && \
    pip3 install -r requirements.txt


