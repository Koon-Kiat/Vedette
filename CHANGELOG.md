# Changelog

## Unreleased

### Dashboard

- A local dashboard on http://127.0.0.1:8080 (FastAPI, Jinja2, vendored
  htmx): Overview, Findings, Domains, Devices, Digests, Health and an
  Evaluation placeholder. Off until `DASHBOARD_TOKEN` is set.
- Triage from the Findings list or a finding's page: Acknowledge, Benign and
  Reopen. Benign on a domain finding allowlists its root for that profile,
  and the rules pick it up within about 30 seconds; Reopen undoes it.
- Every triage action is recorded in a new audit log, shown as the finding's
  history. Migration `0005` adds the audit log and the stored allowlist.
- New command: `sentinel benign <finding>`.
- Security: published on 127.0.0.1 only, token login with a one-time nonce
  and a throttle, `HttpOnly` `SameSite=Strict` session cookie, CSRF token on
  every write, strict Content-Security-Policy, `X-Frame-Options: DENY`, host
  name check, autoescaping everywhere, defanged domains and no links built
  from log data. An XSS test suite covers every page.
- Queries per hour are drawn as SVG on the server instead of with a chart
  library.

### Notifications and health monitoring

- Delivery through ntfy, a Discord webhook or e-mail, chosen by
  `notify.channel`; secrets only from the environment. `none` keeps every
  message without sending it.
- Instant alerts for fresh high and critical findings, with a 60-minute
  cooldown per rule, profile, device and target, and quiet hours that hold
  non-critical alerts.
- Daily digest at the configured local time: findings grouped and ranked, new
  devices, query volume and blocking against the 7-day average, and health.
  Archived as text and JSON. `docs/example-digest.txt` is rendered from test
  data.
- A durable outbox with retries and backoff, so restarts and network loss lose
  nothing.
- Health monitor: profile silence (with per-profile windows and quiet hours),
  NextDNS errors, the local model, the processing backlog and disk space, with
  alerts on change and "Resolved" messages.
- `/healthz` on 127.0.0.1 inside the container, used by Docker's health check.
- New commands: `sentinel notify --test` and `sentinel digest`.
- The collector reports to the health monitor; a quiet stream is no longer
  counted as an error.

### LLM analyst

- Findings are explained by the local model through Ollama's chat API with a
  JSON schema: summary, likely cause, recommended action, priority, group key
  and confidence.
- Guards enforced in code: priority can never drop below the rule's floor,
  answers that do not fit the schema are discarded, model text is stripped of
  HTML, markdown and links and defanged, and the model is given no tools.
- One retry on an invalid or incomplete answer, then a template explanation.
  While Ollama is unreachable nothing is stored and the worker retries.
- Verdict cache keyed by rule, target and a feature hash, with a TTL.
- `sentinel findings` shows the explanation and any raised priority.
- `pytest --live` runs a smoke test against the real model.

### Log export import

- `sentinel import FILE --profile NAME` loads a NextDNS dashboard log export.
  Events get the same ids as their API twins, so nothing is stored twice.
- The `imports/` folder is mounted read-only into the container for this.
- Raw mode now includes the query type in event ids, fixing collisions between
  the A, AAAA and HTTPS lookups of one name.

### Enrichment, rules and findings

- Enrichment from local, cached data: first-seen per profile and device,
  Tranco popularity rank, domain registration age via RDAP, threat-feed matches
  (Phishing Army and CERT Polska) and lexical features.
- Eight declarative rules in `rules.yaml` with severity floors, descriptions,
  thresholds and evidence fields; every rule works with and without device
  attribution. Allowlist per root, optionally per profile or device.
- Findings are stored with de-duplication and listed by `sentinel findings`
  (filters, JSON output, defanged domains, control characters removed).
- Enricher and rule-engine stages run in the pipeline; events are marked
  processed in the same transaction that stores their findings.
- A root hosted on a ranked platform is treated as infrastructure, which
  removed nearly all `dga-like` noise on real traffic.
- New settings: `enrich.*`, `rules.*` and `allowlist`.

### NextDNS collector

- `DnsEvent` model and `LogSource` interface; `NextDnsSource` reads paginated
  history and the resumable live stream, read-only, with TLS verification on.
- Deterministic event ids (NextDNS log entries carry none), so storing an
  event twice keeps one row.
- Exponential backoff with jitter; `429` and `Retry-After` are honoured.
- SQLite storage in WAL mode with Alembic migrations applied at start-up.
- Per-profile collector: backfill, then stream; each stream event is committed
  together with its cursor, and a rejected cursor falls back to re-reading
  history from the last fully synced moment.
- New settings: `ingest.page_size` and `storage.database_url`.
- Integration tests replay a synthetic NextDNS API and kill the collector
  mid-backfill and mid-stream: no gaps, no duplicates.

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
