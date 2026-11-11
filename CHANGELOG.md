# Changelog

## Unreleased

### Scaffold

- Repository layout from the spec, packaged as `nextdns-sentinel` with the
  `sentinel` command.
- Configuration loading from `config.yaml`, environment variables
  (`SENTINEL_` prefix, `__` nesting) and Docker secrets, with validation and
  one-line error messages. Secrets are refused in the YAML file.
- JSON logging to stdout with redaction of sensitive keys, header mappings and
  known secret values, for both Sentinel code and library logs.
- Queue interface with an in-memory implementation.
- `sentinel run` starts a pipeline of idle placeholder stages and shuts down
  cleanly on SIGINT or SIGTERM.
- Docker Compose stack: hardened `sentinel` container, `ollama` with GPU access
  on an internal-only network, a one-shot `ollama-pull` helper, and a `dev`
  container for lint, type checks and tests.
- CI workflow (ruff, mypy `--strict`, pytest on Python 3.14 and 3.15, pip-audit,
  gitleaks) and a Docker-based gitleaks pre-commit hook.
- `.env.example`, `config.example.yaml`, README quickstart and
  `docs/ARCHITECTURE.md` with the decisions taken so far.
