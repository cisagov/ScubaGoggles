# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SCUBAGOGGLES_OPA_DIR=/opt/opa \
    SCUBAGOGGLES_OUTPUT_PATH=/output

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY scubagoggles-src /tmp/scubagoggles-src
COPY opa-bin/opa /tmp/opa

RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install /tmp/scubagoggles-src \
    && mkdir -p /opt/opa /output \
    && install -m 0755 /tmp/opa /opt/opa/opa \
    && /opt/opa/opa version \
    && rm -rf /tmp/scubagoggles-src /tmp/opa

COPY entrypoint.sh /usr/local/bin/scubagoggles-access-token-entrypoint

RUN chmod 0755 /usr/local/bin/scubagoggles-access-token-entrypoint \
    && groupadd --system scuba \
    && useradd --system --gid scuba --home-dir /home/scuba --create-home scuba \
    && chown -R scuba:scuba /home/scuba /opt/opa /output

USER scuba
WORKDIR /output
VOLUME ["/output"]

ENTRYPOINT ["scubagoggles-access-token-entrypoint"]
CMD []
