FROM python:3.6-alpine as base

LABEL maintainer = "Felix Fennell <felnne@bas.ac.uk>"

RUN apk add --no-cache libffi-dev openssl-dev python3-dev

FROM base as build

RUN apk add --no-cache build-base gcc cargo curl
RUN curl -sSL https://install.python-poetry.org | python3 -

ENV PATH="/root/.local/bin:$PATH"
COPY pyproject.toml poetry.lock /
RUN poetry config virtualenvs.in-project true
RUN poetry install --no-root --no-interaction --no-ansi

FROM base as run

COPY --from=build /root/.local/share/pypoetry /root/.local/share/pypoetry
COPY --from=build /root/.local/bin/poetry /root/.local/bin/poetry
COPY --from=build /.venv/ /.venv
ENV PATH="/venv/bin:/root/.local/bin:$PATH"
RUN poetry config virtualenvs.in-project true
ENTRYPOINT []
