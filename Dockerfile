FROM python:3.14-slim-bookworm

RUN apt-get update && \
    apt-get install -y --no-install-recommends postgresql-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 7000 payd && \
    useradd --system --uid 7000 --gid payd --home /home/payd --create-home payd

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PYTHONIOENCODING=utf-8 \
    TERM=xterm-256color \
    UV_CACHE_DIR=/tmp/uv-cache \
    PATH="/home/payd/app/.venv/bin:${PATH}"

WORKDIR /home/payd/app
RUN pip install --no-cache-dir uv==0.8.15

COPY --chown=payd:payd pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache --compile-bytecode --no-dev && \
    rm -rf /tmp/uv-cache


COPY --chown=payd:payd . .

RUN chown -R payd:payd /home/payd/app

USER payd


RUN mkdir -p media staticfiles logs

EXPOSE 8000

ENTRYPOINT ["/home/payd/app/entrypoint.sh"]