FROM python:3.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends postgresql-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    pip install uv

RUN useradd --create-home payd && \
    mkdir -p /home/payd/app && \
    chown -R payd:payd /home/payd/app

WORKDIR /home/payd/app
USER payd

COPY --chown=payd:payd pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache --compile-bytecode

COPY --chown=payd:payd . .

EXPOSE 8000
ENTRYPOINT ["/home/payd/app/entrypoint.sh"]