# syntax=docker/dockerfile:1

# ---- base: Python + uv, shared by the build and dev stages -----------------
FROM python:3.14-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH
COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /uvx /usr/local/bin/
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
FROM python:3.14-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH
RUN groupadd --gid 10001 sentinel \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sentinel \
    && mkdir -p /data /config \
    && chown sentinel:sentinel /data
COPY --from=builder /opt/venv /opt/venv
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["sentinel"]
CMD ["run"]
