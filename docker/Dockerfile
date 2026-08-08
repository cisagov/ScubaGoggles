# syntax=docker/dockerfile:1


# TODO: This used pinned SHAs. Renovate or similar can be added right after this so version bumps
# are tracked automatically. 
ARG PYTHON_REF=3.12-slim@sha256:dd4fe98ab39f91e936f8e7e7a65a3ce59ecfb11e32f9a125b3132779920ba7f7
ARG OPA_REF=1.17.1-static@sha256:c29f8ee8dbe66608a1c04e9be84b04efc46877625e6b0877e559954565209efc

FROM openpolicyagent/opa:${OPA_REF} AS opa

FROM python:${PYTHON_REF} AS builder

WORKDIR /src

COPY pyproject.toml ./

COPY . .

RUN --mount=type=cache,target=/root/.cache/pip \
    pip wheel --no-deps --wheel-dir /wheels .

FROM python:${PYTHON_REF} AS runtime

COPY --from=opa --chown=root:root --chmod=0755 /opa /usr/local/bin/opa

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl

RUN groupadd --system scuba \
    && useradd --system --gid scuba --home-dir /home/scuba --create-home scuba \
    && mkdir /output \
    && chown -R scuba:scuba /home/scuba /output

USER scuba
WORKDIR /output

VOLUME ["/output"]

ENTRYPOINT ["scubagoggles"]
CMD []
