FROM python:3.6-alpine

LABEL maintainer = "Felix Fennell <felnne@bas.ac.uk>"

# Setup project
WORKDIR /usr/src/app

ENV PYTHONPATH /usr/src/app
ENV FLASK_APP manage.py
ENV FLASK_ENV development

# Setup project dependencies
COPY requirements.txt /usr/src/app/
RUN apk add --no-cache libffi-dev libressl-dev python3-dev py-pip && \
    apk add --no-cache --virtual .build-deps build-base && \
    pip install --upgrade pip && \
    pip install -r requirements.txt --no-cache-dir && \
    apk --purge del .build-deps

# Setup runtime
ENTRYPOINT []
