FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

RUN groupadd --system --gid 999 payd && \
    useradd --system --uid 999 --gid 999 --create-home payd
WORKDIR /app

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_NO_DEV=1

ENV UV_TOOL_BIN_DIR=usr/local/bin

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project

COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

    
ENV PATH="/app/.venv/bin:$PATH"
    
RUN mkdir -p media staticfiles && \
chmod +x entrypoint.sh

EXPOSE 8000

ENTRYPOINT []
# RUN apt-get update && \
#     apt-get install -y --no-install-recommends && \
#     apt-get clean && \
#     rm -rf /var/lib/apt/lists/*

# ENV PYTHONDONTWRITEBYTECODE=1 \
#     PYTHONUNBUFFERED=1 \
#     PYTHONHASHSEED=random \
#     PYTHONIOENCODING=utf-8 \
#     TERM=xterm-256color \
#     UV_CACHE_DIR=/tmp/uv-cache \
#     PATH="/home/payd/app/.venv/bin:${PATH}"

# WORKDIR /home/payd/app
# RUN pip install --no-cache-dir uv==0.8.15

# COPY --chown=payd:payd pyproject.toml uv.lock ./
# RUN uv sync --frozen --no-cache --compile-bytecode --no-dev && \
#     rm -rf /tmp/uv-cache


# COPY --chown=payd:payd . .

# RUN chown -R payd:payd /home/payd/app

# USER payd


# RUN mkdir -p media staticfiles && \
#     chmod +x entrypoint.sh

# EXPOSE 8000
