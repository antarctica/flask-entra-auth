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
    apk --purge del .build-deps
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir poetry==1.0.0

COPY pyproject.toml poetry.toml poetry.lock $APPPATH
RUN poetry update --no-interaction --no-ansi
RUN poetry install --no-root --no-interaction --no-ansi

# Setup runtime
ENTRYPOINT []
