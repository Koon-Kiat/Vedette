# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# Every image is pinned to an exact build (@sha256); Dependabot proposes new ones.

# ---- base: Python + uv, shared by the build and dev stages -----------------
FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH
COPY --from=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 /uv /uvx /usr/local/bin/
WORKDIR /app

# ---- builder: locked, hash-verified runtime dependencies only --------------
FROM base AS builder
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

# ---- dev: lint, type-check and test tooling (never deployed) ---------------
FROM base AS dev
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-install-project
COPY . .
RUN uv sync --locked
CMD ["pytest"]

# ---- runtime: no uv, no build tools, non-root -------------------------------
FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH
RUN groupadd --gid 10001 vedette \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin vedette \
    && mkdir -p /data /config \
    && chown vedette:vedette /data
COPY --from=builder /opt/venv /opt/venv
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["vedette"]
CMD ["run"]
