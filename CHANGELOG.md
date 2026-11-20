# Changelog

## Unreleased

### Performance

- The local model's first call after it unloads takes about 4 seconds instead
  of 48 to 60, or about 17 after hours idle, when its weights must be read
  from disk again. CUDA's compiled-kernel cache now lives in the model volume,
  since the read-only root filesystem had made Ollama recompile its GPU
  kernels on every load. The model and its answers are unchanged.
- Calls to the model are sized so the prompt and every answer fit its context
  window, so a batch with long evidence is split instead of being cut short.
- Measured and left as they are: dashboard pages and endpoints answer in 9 to
  220 ms on 400,000 stored queries; the live view's reads cost about 1 ms a
  second and 3 ms every 5 seconds per open page.

### Hardening and evaluation

- Instruction-word pre-filter: a domain finding whose labels contain words
  such as `ignore`, `override` or `benign` gets them added to its evidence and
  its severity raised one step. It never removes anything.
- Retention: raw events are purged after 30 days and findings after 180, with
  their analyses, messages and decisions, by an hourly worker.
  `sentinel purge` runs it now; `sentinel purge --all` wipes all local data.
- The database and everything else Sentinel writes are owner-only (umask 077),
  and existing files are tightened at start-up.
- Ollama now runs as a non-root user with a read-only root filesystem; a
  one-shot `ollama-volume-owner` service hands it the model volume.
- New command: `sentinel backfill` reads a period of history from the API
  without disturbing the live stream.
- New command: `sentinel eval`.
  - It measures detection recall on threat-feed, DGA and tunnelling names,
    false alerts on the top-sites list and on your own history, and the
    prompt-injection success rate on 60 crafted names with the defences on and
    off, with thinking off and on.
  - It also reports schema failures, latency and model load.
  - It writes `docs/EVALUATION.md` and fills the dashboard's Evaluation page.
    Migration `0006` adds the stored runs.
- `docs/THREAT_MODEL.md`: STRIDE over the data flow, with the mitigation in
  the code and the residual risk for each threat.

### Dashboard evaluation fixes

An evaluation against usability heuristics, recorded in
`docs/ux/evaluation-dashboard.md`, found these, now fixed:

- Findings tables fold their secondary columns whenever the table, not the
  window, is too narrow, so the decision buttons stay in view on a
  1,280-pixel laptop.
- After a decision, keyboard focus stays in the row and the decision is
  announced to screen readers.
- A finding's page separates the evidence from when it fired from what the
  caches know now, and says where they differ (rank, domain age). Evidence
  fields are labelled in words, and NextDNS's "default" reads "allowed".
- Devices says a profile sent no queries in 7 days instead of claiming it
  reports no devices.
- Health shows numbers as numbers ("935.5 GB", not "935[.]5 GB"), and a
  failing silence check names the profile settings that quiet it.
- Error pages keep the menu for a logged-in owner and name a missing
  finding; the login error is tied to its field and says the token must match
  exactly.
- A skip link jumps past the menu.
- Static files are versioned by content and revalidated, so an upgrade never
  meets a stale stylesheet.
- Smaller fixes: the Overview lead, the Domains registration column, the
  digest time on the empty Digests page, a plural on Evaluation, and charts
  that keep coarse bars after widening.
- From a second pass on real data:
  - The live feed keeps rows in time order when a query reaches the
    collector late, instead of putting it on top.
  - The live pill sits on the title's line, and a hairline now separates
    "Live" from the figures; it says "1 query" for one.
  - On a phone, a finding card's buttons stay inside the card, the Today
    table scrolls inside its panel, and section notes drop under their
    heading.
  - Chart legends wrap between items, never inside one; the y-axis shows
    1,250 as "1.25K"; evidence labels use the label type.

### Interactive charts

- The "Queries over time" charts on the Overview and the Live page are
  interactive, drawn by uPlot 1.6.32 (MIT), served by the dashboard itself
  and checked by hash.
  - Ranges from 30 minutes to 30 days; drag or Ctrl + scroll to zoom, with
    finer bars fetched as you go; Shift + scroll or Shift + drag to move
    through time; a double-click to go back to live.
  - Exact numbers on hover, finding markers that open their finding, and a
    click on a bar lists what happened then.
  - Enlarge opens the same chart over the whole window.
  - Full keyboard use: arrows, Enter, plus and minus, 0.
- The charts follow live: each query from the live stream joins its bar as it
  arrives.
- New endpoints: `/api/series` and `/partials/window`. The chart partial that
  the Overview polled every minute is gone.
- The Overview chart spans the full width; "Right now" sits next to "New
  devices and findings".
- Wide and ultrawide screens: the dashboard fills up to 3,200 pixels instead
  of stopping at 1,320, and from 2,240 pixels the Overview becomes two
  columns, the Live page sets the feed beside the chart, Domains shows its
  four lists in one row and a finding's page splits its main column. A wider
  chart fetches finer bars, and Enlarge fills the window.
- The list of what happened in a period shows "Most looked up" and "Latest
  queries" as two matching tables whose rows line up.

### Dark, live dashboard

- Dark only: the night-chart theme replaces the light one.
- Mona Sans and JetBrains Mono, self-hosted (OFL) and checked by hash.
- Live updates over server-sent events: counts, pipeline status, new findings
  (they arrive under a magenta wash) and a query feed, with no reload.
- A new Live page streams every query with pause, an only-blocked filter, a
  profile filter and queries per minute for the last 30 minutes. The
  Overview gains "Right now" and a live line.
- Motion: arrivals open their own space so nothing jumps; the live dot pings
  on new data; counters tick when they change. All of it is reduced under
  prefers-reduced-motion.
- Findings tables fold their secondary columns at laptop widths, so the
  decision buttons stay in view.

### Dashboard redesign

- A new visual system, "notices and chart corrections", recorded in
  `DESIGN.md`:
  - A navy navigation rail with the open-findings count and pipeline status.
  - Findings set as numbered notices, with the reason on high and critical
    rows and a bar showing when each was seen that day.
  - Triage decisions drawn in magenta: the old status struck, the new one
    written in with its time.
  - Queries per hour drawn against the usual level, with open findings marked
    by number.
  - On a phone, findings stack as cards with the actions in reach.
- Light and dark ("night chart") themes; sloped type marks every name that
  came from outside.

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
