# NextDNS Sentinel

A self-hosted pipeline that ingests NextDNS query logs, flags suspicious DNS
activity with deterministic rules, uses a **local** LLM (Ollama) only to explain
and prioritise what the rules surface, and sends a daily digest plus real-time
alerts.

- **Cheap:** no paid APIs and no cloud LLM.
- **Private:** DNS history and analysis stay on your machine.
- **Hardened:** domain names are attacker-controlled text; the LLM stage is
  built to resist prompt injection, and rules alone decide whether an alert fires.

## Status

Only the scaffold exists so far: configuration loading, redacted JSON logging,
the queue interface, hardened containers and CI. `docker compose up` starts a
pipeline whose stages are idle placeholders. Nothing contacts NextDNS yet. See
[CHANGELOG.md](CHANGELOG.md) for progress and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and decisions.

## Requirements

- Windows 11 with WSL2 and Docker Desktop (WSL2 backend), running.
- An NVIDIA GPU with a current Windows driver, for Ollama.
- Nothing else is installed on the host: Python, uv and every tool run in Docker.

## Quickstart (Windows 11 + Docker Desktop)

Run these in PowerShell from the repository folder.

```powershell
Copy-Item .env.example .env
Copy-Item config.example.yaml config.yaml
```

(bash: `cp .env.example .env && cp config.example.yaml config.yaml`)

1. Edit `.env` and set `NEXTDNS_API_KEY` (bottom of your NextDNS account page).
2. Edit `config.yaml` and replace `ROUTER_PROFILE_ID` with the ID shown on the
   profile's Setup page in the NextDNS dashboard.
3. Download the model once (about 5.2 GB for `qwen3:8b`):

   ```powershell
   docker compose --profile setup run --rm ollama-pull
   ```

4. Start the stack:

   ```powershell
   docker compose up --build -d
   docker compose logs -f sentinel
   ```

Stop it with `docker compose down`. Data lives in the named volumes
`sentinel-data` and `ollama-models` and survives restarts.

## Configuration

- `config.yaml` holds all non-secret settings; `config.example.yaml` documents
  each one with its default.
- Any value can be overridden by an environment variable: prefix `SENTINEL_` and
  put `__` between nesting levels, for example `SENTINEL_LLM__MODEL=qwen3:8b`.
- Secrets come only from environment variables or Docker secrets, never from
  `config.yaml`. `.env.example` lists every variable.

## Development

All tooling runs in the `dev` container:

```powershell
docker compose --profile dev build dev
docker compose --profile dev run --rm dev ruff check .
docker compose --profile dev run --rm dev ruff format --check .
docker compose --profile dev run --rm dev mypy
docker compose --profile dev run --rm dev pytest
```

Enable the secret-scanning commit hook once per clone (it runs gitleaks through
Docker, so nothing is installed on the host):

```powershell
git config core.hooksPath .githooks
```

If you already use [pre-commit](https://pre-commit.com), `.pre-commit-config.yaml`
provides the same gitleaks check.

## Troubleshooting

- **`env file .env not found` or a bind-mount error for `config.yaml`:** run the
  two `Copy-Item` commands above.
- **`could not select device driver "nvidia"`:** update the NVIDIA Windows driver
  and make sure Docker Desktop uses the WSL2 backend.
- **Docker commands fail to connect:** start Docker Desktop and wait for it to
  finish starting.
