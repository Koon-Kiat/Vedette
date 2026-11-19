# Architecture

NextDNS Sentinel is five stages joined by a queue, so each stage can restart,
retry and scale on its own. Deterministic code handles almost everything; the
local LLM sees only the small, already-filtered remainder and can never lower
or suppress what the rules decided.

```text
NextDNS API (per profile)
  /logs (backfill) + /logs/stream (SSE, resumable)
        |
        v
[1 Collector] --> raw events --> [queue: events]
                                      |
                                      v
[2 Normaliser + Enricher]  first-seen, popularity rank, domain age (RDAP),
                           threat-intel match, entropy/DGA score, device info
        |
        v
[3 Rule engine]  deterministic detections -> Finding(severity floor, evidence)
        |                          |
        | (low/info, batched)      | (high/critical, immediate)
        v                          v
[4 LLM analyst (Ollama)]     [5 Notifier] -> instant alert
  explain, group, may RAISE priority only
        |
        v
[5 Notifier] -> daily digest
```

## What exists today

| Piece | Where | State |
| --- | --- | --- |
| Configuration | `src/sentinel/config.py` | Done: YAML + environment overrides + Docker secrets, validated |
| Logging | `src/sentinel/log.py` | Done: JSON to stdout, secrets redacted |
| Queue interface | `src/sentinel/pipeline/queue.py` | Done: `EventQueue` with an in-memory implementation |
| Event model and source interface | `src/sentinel/sources/base.py` | Done: `DnsEvent`, `LogSource` |
| NextDNS source | `src/sentinel/sources/nextdns.py` | Done: history paging, live stream, backoff |
| Log export reader | `src/sentinel/sources/nextdns_export.py` | Done: `sentinel import` loads a dashboard CSV export |
| Storage | `src/sentinel/storage/` | Done for events, collector state, findings, reference data, the stored allowlist, the audit log and evaluation runs: SQLite (WAL), Alembic migrations, retention purge, owner-only files |
| Collector | `src/sentinel/pipeline/collector.py` | Done: backfill, stream, resume, gap-fill |
| Enrichment | `src/sentinel/enrich/` | Done: first-seen, popularity, domain age (RDAP), threat feeds, lexical features |
| Rules | `src/sentinel/rules/` | Done: eight declarative rules, allowlist, deterministic engine, instruction-word pre-filter |
| Enricher and rule workers | `src/sentinel/pipeline/processor.py` | Done |
| Defanging | `src/sentinel/notify/defang.py` | Done: CLI, alerts and digests |
| LLM analyst | `src/sentinel/llm/`, `src/sentinel/pipeline/analyst.py` | Done: Ollama client, schema, guards, cache, template fallback |
| Notifier | `src/sentinel/notify/`, `src/sentinel/pipeline/notifier.py` | Done: ntfy, Discord and e-mail; outbox; quiet hours; daily digest |
| Health monitor | `src/sentinel/health/` | Done: six kinds of check, alerts on change, `/healthz` |
| Pipeline runner | `src/sentinel/pipeline/runner.py` | Runs all six stages, `/healthz`, the dashboard and the hourly retention purge |
| CLI | `src/sentinel/cli.py` | `sentinel run`, `findings`, `benign`, `backfill`, `import`, `notify --test`, `digest`, `purge`, `eval`, `--version` |
| Dashboard | `src/sentinel/web/`, `src/sentinel/storage/dashboard.py`, `src/sentinel/storage/triage.py` | Done: seven pages, triage with an audit log, token login; visual system in `DESIGN.md` |
| Evaluation | `src/sentinel/eval/` | Done: datasets, offline detection, prompt-injection test with defences on and off, history metrics, `docs/EVALUATION.md` |

## How the collector avoids gaps and duplicates

1. **Take the stream position first.** A backfill starts by asking NextDNS for
   the most recent logs, which returns `meta.stream.id`. Only then is history
   read. Anything that arrives while history is being read is delivered by the
   stream afterwards.
2. **Store idempotently.** NextDNS log entries have no id, so the event id is a
   SHA-256 of profile, timestamp, domain, status, protocol, device id and
   client IP. It is the primary key, and inserts ignore conflicts, so overlap
   between history and stream collapses to one row.
3. **Move the resume point only when data is on disk.** History arrives newest
   first, so pages do not touch the collector state. The stream cursor and
   `synced_through` are written when the backfill completes, and afterwards in
   the same transaction as each stream event.
4. **Restart.** With a stored cursor the collector reopens the stream from it
   and reads no history. Without one (killed mid-backfill) it repeats the
   backfill, which is harmless because of point 2.
5. **Rejected cursor.** The cursor is cleared and history is re-read from
   `synced_through` minus a 5-minute overlap, which also yields a fresh cursor.

Failures are handled without stopping: transient errors and `429` back off
exponentially with jitter (or wait for `Retry-After`), a rejected API key is
retried every 5 minutes, and any unexpected error is logged with its traceback
and retried after 30 seconds.

## How events become findings

1. **Enricher worker.** Reads stored events that have not been through the
   rules, oldest first, 500 at a time, for each profile whose collector holds a
   stream cursor (so never while a backfill is in flight). It adds:
   - first-seen flags for device, client IP, root and category;
   - the root's rank in the top-sites list, and the best rank among the root's
     parent domains (`platform_rank`);
   - the root's registration age from the RDAP cache, with a live lookup only
     when the root is allowed, unranked, not on a ranked platform, and the
     event is less than 24 hours old;
   - matches against the threat feeds, for the name and each parent down to
     its root;
   - lexical features of the leftmost label.
2. **Queue.** The enriched batch is published and the enricher waits until it
   has been acknowledged, so at most one batch is in flight.
3. **Rule worker.** Evaluates every rule, then in one transaction stores the
   findings and marks the batch's events processed. A crash before that commit
   leaves the events unprocessed, so they are enriched and evaluated again:
   nothing is lost and nothing is counted twice.
4. **Findings.** Each has a de-duplication key (rule, profile, device, target
   and a time bucket). Repeats merge into one row with a count and a first and
   last time; the evidence of the first sighting is kept.

The rule engine keeps sliding windows and hourly baselines in memory. After a
restart it rebuilds them by replaying the fields of already-processed events
from the last week, without producing findings.

### Rules

Rules live in `src/sentinel/rules/rules.yaml`: id, severity floor, description,
thresholds and evidence fields. The detector behind each id is code. A file
named by `rules.file` in the config can override any value per rule id.

When an event has no device id, per-device rules count per profile, and the
finding records that device attribution is unavailable. Rules that compare
against history (`new-device`, `volume-spike`, `new-destination-category`) stay
quiet for the first `rules.learning_days` (3) after a profile's oldest event.

## How findings get explained

The analyst worker polls for findings without an analysis, most severe first,
and handles up to `llm.max_findings_per_batch` (20) at a time. Each finding
always ends with a valid analysis, from the first of these that applies:

1. **Cache.** A fresh verdict for an equivalent earlier finding. The key is the
   prompt version, model, rule, target, attribution mode and a hash of coarse
   evidence features (exact subdomains left out, numbers bucketed by powers of
   two), so a finding that recurs the next day is not sent to the model again.
2. **Model.** One call to Ollama's chat API with the JSON schema in `format`,
   `think` off, temperature 0.1, `num_ctx` 8192 and `keep_alive` 5m. The answer
   must parse into the schema or it is discarded whole. An invalid or
   incomplete answer is retried once.
3. **Template.** Text built from the rule's own description and the defanged
   target, at the rule's floor, marked as not written by the model.

If Ollama cannot be reached, nothing is stored and the worker retries with
backoff (5 seconds up to 5 minutes). Findings exist and are listed regardless.

### Prompt-injection defences in this stage

| Defence | Where it is enforced |
| --- | --- |
| Rules own severity: the model may raise priority, never lower it | `enforce_floor` in `llm/guards.py`, applied in code after validation, to cached verdicts too |
| The model cannot suppress a finding | Findings are stored before the analyst runs; it only adds an analysis |
| Untrusted strings are data, not instructions | `build_payload` in `llm/prompts.py`: they appear only as length-capped values in a JSON payload; the system prompt is fixed |
| Structured output only | `parse_verdicts` in `llm/schema.py`: extra fields, wrong types and free text are rejected |
| No tools | `llm/ollama.py` never sends a `tools` field; the Ollama container has no internet route |
| Safe output | `sanitize_model_text`: HTML, markdown and links removed, names defanged, length capped; applied again on display |

Not done yet: the deterministic pre-filter that flags instruction-like words in
labels, and measuring the injection success rate. Both belong to the hardening
and evaluation work.

## How alerts, digests and health messages are sent

Every message goes through an outbox table before anything is sent, together
with what happened to it (`pending`, `sent`, `failed`, `skipped`,
`suppressed`). Three workers use it:

1. **Alert worker** (every 2 seconds). Picks up findings whose effective
   priority is high or critical and that have no outbox entry yet. A finding
   whose own floor is high or critical waits up to 60 seconds for the model's
   explanation. Each finding gets exactly one entry: `pending`, `skipped`
   (`too_old`, last event over an hour ago) or `suppressed` (`cooldown`, the
   same rule, profile, device and target was alerted within the last hour).
2. **Delivery worker** (every 2 seconds). Sends due entries through the
   configured channel. During quiet hours it holds high alerts and health
   messages until the hours end; critical alerts and digests go immediately.
   Failures that may pass are retried with backoff from 30 seconds up to an
   hour (or the channel's `Retry-After`), at most 10 attempts; others fail at
   once. With no channel configured, entries are marked `skipped`.
3. **Digest scheduler** (every minute). At the configured local time it builds
   the digest for the previous 24 hours, archives it (text and JSON) and
   queues it, in one transaction. The first digest comes at the first digest
   time after the service starts; if digests were missed while it was down,
   only the most recent is produced, late.

### Health monitor

Runs every 60 seconds. Per enabled profile: silence (no events for
`stale_after_minutes`, not counting the profile's own `quiet_hours`) and
NextDNS errors (the collector reports every success and failure; an open
stream that is simply quiet is not an error). Then: the local model (Ollama's
model list, and that the configured model is downloaded), the backlog of
events waiting for the rules, and disk space where the database lives.

A check that goes bad raises a health alert at once. It counts as recovered
after two good checks in a row, and then a "Resolved" message is sent. What
the user was last told about each check is read back from the outbox, counting
only messages that were sent or are queued, so a restart neither repeats an
alert nor forgets to resolve one.

Results are stored for the digest and the dashboard, and served by `/healthz`
on 127.0.0.1 inside the container: 503 until the first check and if checks
stop running, otherwise 200 with `ok` or `degraded`. Docker's health check
calls it, so container health means "the service is running its checks".

### Channels

| Channel | Format | Safeguards |
| --- | --- | --- |
| ntfy | JSON publish to the server root; plain text (Markdown off); priority 1 to 5 from severity | Body capped at 4,000 bytes (ntfy turns larger messages into attachments); `https` required except for a server on the local Docker network |
| Discord | Webhook with `?wait=true` | Every formatting character escaped, `allowed_mentions: {parse: []}`, link previews suppressed (flag 4), at most ten 1,900-character parts, short rate limits waited out |
| E-mail | `text/plain` over SMTP | STARTTLS or implicit TLS only, certificate checked, subject cleaned so it cannot add headers |

Error messages never contain the topic, token, webhook URL or password.

## The dashboard

FastAPI renders every page on the server with Jinja2; htmx (vendored, no CDN)
swaps the findings table when a filter changes and a single row after a
triage action. Pages work without JavaScript too: the forms post normally and
redirect back. The server runs inside the pipeline process, on the same
database engine, and stops with it.

Everything shown can come from an attacker: domain names, device names,
blocklist reasons and the model's text. So:

- **Escaping.** Autoescaping is on for every template, undefined variables are
  errors, and a test fails any template that uses `|safe` or turns
  autoescaping off. Domains are always defanged (`example[.]com`) and never
  links; every link is a fixed path of the dashboard's own, at most with a
  finding or digest number in it.
- **Browser policy.** Every response carries `Content-Security-Policy` with
  `default-src 'self'` and nothing inline allowed (no `unsafe-inline`, no
  `unsafe-eval`), `frame-ancestors 'none'`, `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` and
  `Cache-Control: no-store` (static files excepted).
- **Login.** One token from `DASHBOARD_TOKEN`, compared in constant time. The
  login form carries a one-time nonce that must match a cookie scoped to
  `/login`, so another site cannot log the browser in. Five failures within a
  minute refuse logins for a minute.
- **Session.** A random id in an `HttpOnly`, `SameSite=Strict` cookie; the
  token itself is never stored in a cookie. Sessions are held in memory and
  expire after `dashboard.session_hours`.
- **Writes.** Every POST needs the session's CSRF token, as a form field or
  the `X-CSRF-Token` header that htmx sends. Each triage action and its audit
  log entry are written in one transaction.
- **Reach.** The container publishes the port on `127.0.0.1` only, and the
  app answers only to the host names in `dashboard.allowed_hosts`, which stops
  DNS rebinding from a web page.

The XSS test suite plants payloads in every field that can reach a page, then
parses every page and the row returned after an action: the only scripts are
our own static files, no element has an event-handler attribute, no URL uses
`javascript:` or `data:`, every link stays inside the dashboard, and the
payload text appears escaped rather than dropped.

## Containers

| Service | Purpose | Network | Hardening |
| --- | --- | --- | --- |
| `sentinel` | The pipeline and the dashboard | `egress` (to api.nextdns.io) and `llm` | uid 10001, read-only root filesystem, all capabilities dropped, `no-new-privileges`; one published port, the dashboard on `127.0.0.1:8080` |
| `ollama` | Local model server with GPU | `llm` only (internal: no internet, no host port) | uid 10002, read-only root filesystem, all capabilities dropped, `no-new-privileges` |
| `ollama-volume-owner` | One-shot: hands the model volume to uid 10002 before Ollama starts | none | root with only `CHOWN` and `DAC_READ_SEARCH`, read-only root filesystem, `no-new-privileges` |
| `ollama-pull` | One-shot model download (`setup` profile) | `egress` | uid 10002, read-only root filesystem, all capabilities dropped, `no-new-privileges` |
| `dev` | Lint, type-check, tests (`dev` profile) | `egress` | Development only, never deployed |

## Decisions

1. **Repository root is this folder.** The spec's `nextdns-sentinel/` tree maps
   onto the repository root.
2. **Only dependencies in use are declared.** Each part of the spec's stack is
   added when the code that needs it lands, so the audited dependency set stays
   as small as possible.
3. **`hatchling` builds the package.** A build backend is required to install
   the `sentinel` console script; hatchling is small and widely used.
4. **`tzdata` and `pyyaml` are direct dependencies.** `python:3.14-slim` has no
   system time zone database, and the config loader parses YAML itself so it
   can refuse secrets placed in the file.
5. **Dependencies are pinned with hashes in `uv.lock`.** Images install with
   `uv sync --locked`, which verifies every hash. `pip-audit` runs against a
   hashed export of the same lock file.
6. **Secrets never come from `config.yaml`.** The loader rejects
   `nextdns_api_key` in YAML outright. `NEXTDNS_API_KEY` is read from the
   environment or from a Docker secret of the same name.
7. **Environment overrides use `SENTINEL_` and `__`.** For example
   `SENTINEL_LLM__MODEL`. Lists take JSON. Unknown keys in the YAML file are
   errors so that typos surface at start-up.
8. **The notification channel is undecided.** `notify.channel` is kept as free
   text with the placeholder `NOTIFY_CHANNEL` and is not validated until the
   notifier is built.
9. **Ollama has no route to the internet.** It sits on an `internal` Compose
   network. Models are downloaded by the one-shot `ollama-pull` service, which
   has internet access, shares the model volume, and exits. `OLLAMA_NO_CLOUD`
   is set so the server does not try to reach ollama.com.
10. **Ollama ran as root until the hardening work** (decision 64 replaces
    this).
11. **Secret scanning runs through Docker.** `.githooks/pre-commit` runs a
    pinned gitleaks image on staged changes, so the "install nothing on the
    host" rule holds. CI runs the same image over the full history.
12. **The queue contract is at-least-once.** A message counts towards queue
    depth until it is acknowledged. The in-memory queue is not durable;
    durability across restarts comes from the collector's stored cursor and
    idempotent event ids.
13. **Base images are pinned by version tag**, not by digest
    (`python:3.14-slim`, `ollama/ollama:0.40.16`, `ghcr.io/astral-sh/uv:0.13.7`,
    `ghcr.io/gitleaks/gitleaks:v8.30.1`). Digest pinning is listed under future
    work.

14. **The events table is the hand-off from the collector.** The collector
    stores events; the enricher reads unprocessed ones from storage in
    timestamp order. That keeps a 160,000-event backfill out of memory, puts
    newest-first history back in order, and makes the hand-off durable. The
    queue sits between the enricher and the rule engine.
15. **Alembic manages the schema.** Migrations live in
    `src/sentinel/storage/migrations` and run at start-up over a synchronous
    connection. A test checks they match the table definitions.
16. **One transaction per stream event.** Simple and exactly matches "persist
    the cursor with each committed batch". Batching is deferred until load
    testing shows it is needed.
17. **Timestamps are stored as naive UTC** in SQLite, which has no timezone
    type, and are always timezone-aware in code.
18. **Untrusted strings are truncated, not rejected.** An over-long device
    name or reason must not make an event disappear. Entries missing a
    timestamp, domain or status are skipped and counted in a warning.
19. **The stream reconnects after 5 minutes of silence.** NextDNS documents no
    heartbeat, so a quiet stream cannot be told apart from a dead connection.
20. **`sentinel run` backfills automatically**; the manual `sentinel backfill`
    came with the hardening work (decision 65).

21. **External lookups are kept to what the spec's enrichment requires, and
    each can be changed or turned off.** The spec asks both that "only the
    NextDNS API is called" and for a top-sites list, threat feeds and RDAP.
    The top-sites list and threat feeds are bulk downloads matched locally, so
    they reveal nothing about individual queries. RDAP does reveal the root
    being looked up to its registry, so it is limited to allowed, unranked,
    recent roots (10 lookups for a week of router traffic) and has an
    `enrich.rdap.enabled` switch.
22. **Threat feeds are Phishing Army and CERT Polska by default.** Both
    download without an account. The abuse.ch feeds (URLhaus, ThreatFox) now
    answer HTTP 410 on their public URLs and need a free account key, so they
    are not included. Check each feed's terms before adding or keeping it.
23. **A root's parent domain counts for popularity.** NextDNS reports customer
    hostnames on cloud and CDN platforms as roots of their own (three or more
    labels). They are absent from the top-sites list and are not registered
    domains. `platform_rank` records the best rank among a root's parents;
    `young-domain` and `dga-like` need both ranks to be absent, and RDAP is
    skipped. `threat-intel-allowed` deliberately ignores `platform_rank`,
    because phishing hosted on a popular platform is exactly what it should
    catch. Trade-off: a random-looking name on a popular platform is not
    flagged by `dga-like`.
24. **A feed entry never taints its parent or siblings**, and a feed match on a
    root ranked in the top 1,000 is distrusted, which limits the damage a
    wrong or compromised feed can do. A failed or empty download keeps the
    previous data.
25. **Rule state is in memory, rebuilt from storage.** No separate state table
    to keep consistent; a restart replays about a week of event fields.
26. **An unexpected error in the rule worker stops the process.** Engine state
    would no longer match storage, so the container restarts clean rather than
    carrying on. The collector and enricher log and retry instead.
27. **The allowlist started as configuration only.** "Mark benign" from the CLI
    or dashboard now adds to it (decision 56).
28. **The instruction-word pre-filter came with the hardening work**
    (decision 61).

29. **History can also come from a log export; the stream stays on the API.**
    `sentinel import` loads the dashboard's CSV export for a profile. It is an
    extra way in, not a replacement: real-time alerts and unattended running
    need the stream. The file is not downloaded automatically, because the
    export is the raw view of the whole retention period.
30. **Query type is part of the event id in raw mode only.** In raw mode NextDNS
    reports the A, AAAA and HTTPS lookups for one name as separate entries with
    the same timestamp; without the type they collided (317 of 1,172 rows in
    the tested export). In default mode entries carry no type and ids are
    unchanged, so existing data is unaffected.
31. **The importer does not imitate NextDNS's removal of repeats.** That rule
    is undocumented. In default mode an imported period therefore holds more
    events than a collected one, which can make volume baselines for that
    period look higher. The command says so every time; `ingest.raw: true`
    removes the difference.

32. **One verdict per finding, many findings per call.** The response is
    `{"verdicts": [...]}` keyed by `finding_id`; a missing verdict is treated
    like an invalid answer for that finding only.
33. **Invalid twice means a template; unreachable means wait.** A poison
    finding cannot loop forever, and an outage cannot fill the database with
    templates that would hide the model's absence.
34. **Template fallbacks are never cached.** Only model verdicts are.
35. **Model text is stored already sanitised and defanged.** Prose is defanged
    with `defang_text`, which brackets only dots inside names so that sentence
    punctuation survives.
36. **`sentinel findings --min-severity` uses the effective priority**: the
    analysis's if there is one, otherwise the rule's floor.
37. **Every model call is recorded** (time, duration, findings, outcome) for
    the health page and the evaluation report to come.
38. **The dev container joins the internal `llm` network** so `pytest --live`
    can reach the model. It is never deployed.

39. **A durable outbox for every message.** Alerts survive restarts and
    network loss, every decision (sent, too old, cooldown, no channel) can be
    seen later, and a finding can never be alerted twice.
40. **No channel means "kept, not sent".** The spec's `NOTIFY_CHANNEL`
    placeholder is read as `none`. Choosing a channel later does not flood you
    with old alerts: they were already recorded as skipped.
41. **Alerts are for fresh findings.** Only findings whose last event is under
    an hour old (`notify.alert_max_age_minutes`) are alerted, so a first
    backfill or an imported file does not set off a burst of old alerts. They
    still appear in `sentinel findings` and in the digest.
42. **A short wait for the model.** A high or critical finding waits up to
    60 seconds (`notify.analysis_wait_seconds`) so the alert can carry the
    model's explanation; then it is sent without one. Spec: high and critical
    findings go straight to the notifier; this keeps that while adding the
    explanation when it is quick.
43. **The cooldown applies to finding alerts, not to health messages.** Found
    in a live test: with a cooldown, a problem that came back within the hour
    after a "Resolved" message was never reported. Health messages now always
    report a change, and two good checks in a row are needed to count as
    recovered, which absorbs flapping.
44. **Quiet hours hold, they do not drop.** Held messages are sent when quiet
    hours end. Critical alerts and digests are never held; the digest time is
    chosen by the user.
45. **Notification secrets come only from the environment or Docker secrets**
    (`NTFY_TOPIC`, `NTFY_TOKEN`, `DISCORD_WEBHOOK_URL`, `SMTP_PASSWORD`). They
    are refused in `config.yaml`, redacted from logs, and checked at start-up:
    a channel without its secret stops the service with a clear message.
46. **Plain `http` for ntfy only on the local Docker network** (a host name
    without dots, or localhost). E-mail has no unencrypted option.
47. **`/healthz` is a minimal standard-library server**, not a web framework.
    It reads one short request with a timeout and answers only `GET /healthz`.
    It stayed separate from the dashboard (decision 59).
48. **Docker health means liveness.** `/healthz` stays 200 when a check fails
    (it reports `degraded`), so an offline laptop profile does not make the
    container look broken; the problem is reported by alert and digest.
49. **An idle stream is not an error.** A read timeout after the stream opened
    is reported as `StreamIdle` and the collector reconnects without counting a
    failure.
50. **The digest is built from stored data only** (events, findings, analyses,
    health results), so `sentinel digest` can preview it from the command line,
    and the archive keeps both the text as sent and the numbers as JSON.

51. **The chart is server-drawn SVG, not a chart library.** This departs from
    the spec, which asks for one small vendored chart library. The dashboard
    has a single chart, queries per hour as stacked bars, and under 100 lines
    of Python draw it as SVG with the bars in the markup. That adds no
    third-party JavaScript to review, pin and keep updated; the data never
    passes through JavaScript or inline JSON; it works under the strict CSP
    without exceptions; and it renders with JavaScript off. A library is worth
    adding if the dashboard needs interactive charts.
52. **htmx 2.0.11 is vendored and locked down.** A test checks the file's
    SHA-256 against the reviewed release. Its configuration turns off `eval`
    and script tags in swapped content, allows requests to this origin only,
    and keeps no history cache, so pages are never copied into the browser's
    session storage.
53. **One shared token and in-memory sessions.** The dashboard has one user.
    A restart logs the browser out, which is acceptable for a page on this
    machine and means no session data on disk.
54. **The host name is checked, not just the address.** Listening on loopback
    does not stop a web page from pointing its own name at 127.0.0.1 (DNS
    rebinding); refusing unknown `Host` headers does.
55. **The server listens on all interfaces inside the container.** Docker's
    port publishing needs that; exposure is decided by publishing on
    `127.0.0.1` only. Checked live (see "Verified facts").
56. **Mark benign on a domain rule allowlists the root for that profile.** The
    rules `young-domain`, `threat-intel-allowed`, `dga-like` and `tunnel-like`
    are about a domain; the entry covers the root and its subdomains on the
    finding's profile, not other profiles. For the other rules, Benign only
    changes the status. Reopen removes the entry. Other findings already
    recorded keep their status. The rule worker reloads the allowlist
    (configuration plus stored entries) at most every 30 seconds, before a
    batch.
57. **Web-facing dependencies are pinned exactly** (`fastapi`, `jinja2`,
    `python-multipart`, `uvicorn`), to releases at least two weeks old, as
    well as being locked with hashes.
58. **Less on the wire and in the logs.** FastAPI's `/docs`, `/redoc` and
    `/openapi.json` are off, uvicorn sends no `Server` or `Date` header, and
    there is no access log, so filter values such as device names do not end
    up in the container log.
59. **`/healthz` stays separate.** Docker's health check must reach it without
    a login, and it is not published outside the container.
60. **More pooled database connections.** The dashboard shares the pipeline's
    engine, so the pool grew to 15 connections plus 10 overflow: enough for
    every worker and the dashboard, so new connections are opened mostly at
    start-up. aiosqlite 0.22.1 cannot cancel a connection that is still
    opening; one interrupted by a shutdown is closed later by the garbage
    collector (Python warns about it) and SQLite itself is unaffected. The
    tests wait for start-up to finish before stopping the pipeline.

61. **The pre-filter raises one step and only looks at domain labels.** A hit
    adds `instruction_tokens` to the evidence and raises the severity one level
    (never past critical). Distinctive words (`ignore`, `instruction`,
    `override`, `benign` and others) match anywhere, so run-together names are
    caught. Common words (`system`, `safe`, `mark`, `previous` and others)
    match only as whole words, so `ecosystem` or `marketplace` stay quiet. It
    applies only to findings that already exist: a word alone never creates a
    finding, which keeps ordinary names out of the alerts. Device names are not
    checked (the spec names labels). The rule engine runs it; only the
    evaluation turns it off.
62. **What the retention purge removes.**
    - Processed events older than `retention.events_days`. Events still
      waiting for the rules are kept until processed.
    - Findings whose last sighting is older than `retention.findings_days`,
      with their analyses, outbox messages and audit entries.
    - Health messages, digests and model-call records older than the same
      limit.
    - Allowlist entries made from a purged finding stay in force, with the link
      to the finding cleared.
    - Kept until `purge --all`: the first-seen index (it is what makes
      something "new"), the reference caches and evaluation runs. They hold no
      lookup times.
    The purge runs one minute after start-up and then hourly.
63. **Owner-only files by umask and by repair.** `sentinel` sets umask 077
    before anything else, so the database, its WAL and anything else it
    writes are created 0600. Migrations also tighten an existing file to 0600
    and its directory to 0700, which fixes databases created before this
    change.
64. **Ollama runs as uid 10002 with a read-only root filesystem.** The model
    volume is mounted at `/home/ollama/.ollama` with `HOME=/home/ollama`, so
    the existing models and key keep their paths. A one-shot service runs
    `chown` as root with only `CHOWN` and `DAC_READ_SEARCH` and no network
    before Ollama starts, on every `up`; it takes a moment because it only
    changes metadata. `ollama-pull` runs as the same user. Checked live: the
    model listed, the GPU found, and the real-model smoke test passed with the
    model 100% on the GPU.
65. **`sentinel backfill` adds history without touching the stream.** It reads
    a window through the same history paging the collector uses and stores
    events idempotently. It does not move the stored stream cursor, so the live
    stream carries on unaffected. `--days` is capped at the event retention,
    otherwise the purge would delete what it just read.
66. **How the evaluation is built.**
    - **Detection.** It reuses the real enrichment and rule engine, offline:
      reference data is read from the local tables, registration dates come
      from the cache only (no RDAP), and first sightings go to a scratch
      database. The real database is only read, except for storing the
      result.
    - **Defences off.** A naive analyst kept only in `sentinel/eval/`: names
      written into the instructions, no warning, no pre-filter, no floor
      guard, no sanitising. The JSON schema stays so a priority can be read;
      the report says so.
    - **Echoes.** Counted by a word-pattern heuristic that skips sentences
      describing the attempt. Every counted case is printed in the report,
      with the model's words, so it can be checked.
    - **False alerts, latency and load.** Read from what the pipeline already
      stored, not replayed.
    - **Privacy.** The report and the dashboard show names from your history
      and the feeds only as counts.
    - **Results.** Stored in `eval_runs` for the Evaluation page.
67. **The dashboard's visual system was redesigned.** The direction is
    "notices and chart corrections": a navy rail, a chart-white ground,
    magenta only for attention and decisions, and sloped type for every name
    from outside. It was chosen from a design round, reviewed, and recorded in
    `DESIGN.md`. The system font stack stays: an operating screen needs no
    downloaded face, and the strict CSP allows no external fonts.

## Verified facts the design relies on

Checked against the official NextDNS API documentation on 2026-11-12:

- Entries returned by `/logs` have **no unique id**; only SSE events carry one.
  Event ids will therefore be a deterministic hash of the entry's fields.
- `meta.stream.id` is returned only "when getting the most recent logs", so the
  backfill must query newest-first and capture it from the first page.
- `/logs/stream` accepts every `/logs` parameter except `from`, `to`, `sort`,
  `limit` and `cursor`.
- Rate limits, stream heartbeats and the behaviour of an expired stream id are
  not documented.

Observed on a live run against the owner's router profile on 2026-11-12:

- Log entries carried `timestamp` (ISO 8601 ending in `Z`), `domain`, `root`,
  `tracker`, `encrypted`, `protocol`, `clientIp`, `status` and `reasons`.
  **No entry had `device`**, and there was a single `clientIp`: device
  attribution is unavailable on this profile, as the spec anticipated.
- `meta.stream.id` was also returned when `from` was set. The collector still
  takes it from a plain most-recent request, which is what the docs promise.
- **NextDNS does rate-limit.** After roughly 165 requests in 5 minutes the
  stream endpoint answered `429` with error code `rateLimit` for about 20
  seconds. Successful responses carried no rate-limit headers. The collector
  backed off and recovered without losing data.
- The first backfill read 161 pages and stored 159,849 events in about
  2.5 minutes without being rate-limited.
- A stream with no traffic stayed open for several minutes; one was closed by
  the server after about a minute. Both cases reconnect from the stored cursor.
- Behaviour of an expired stream id: a 6½-day-old id was accepted (see below);
  the age at which NextDNS stops accepting one is still unknown.

Checked on 2026-11-12 for enrichment:

- Tranco's `top-1m.csv.zip` redirects to a daily file: one CSV of
  `rank,domain` rows, one million of them.
- RDAP answers carry an `events` list; the entry with
  `eventAction: registration` holds the registration date. The IANA bootstrap
  file maps each TLD to its RDAP server; some TLDs (for example `.io`) have none.
- Ollama 0.40.16 with `qwen3:8b` (capabilities: completion, tools, thinking;
  thinking defaults to on): the JSON-schema `format` constraint held with
  `think: false` and with `think: true`. With thinking on, the same three
  findings took about four times as many output tokens. The docs do not state
  a minimum version for schema output, so every answer is validated regardless.
- First live analysis of the router profile's two findings: one call, 3.6
  seconds with the model already loaded, both verdicts valid.
- A real log export for the laptop profile (1,172 rows) against the API for
  the same period: the raw API view returned exactly 1,172 entries; the
  default view returned 628, every one of them present in the file with an
  identical event id. Export columns: `timestamp`, `domain`, `query_type`,
  `dnssec`, `protocol`, `client_ip`, `status` (empty means default), `reasons`
  (comma-separated ids, no names), `destination_country`, `root_domain`,
  `device_id`, `device_name`, `device_model`, `device_local_ip`,
  `matched_name`, `client_name`. There is no `encrypted` or `tracker` column.
- The laptop profile does report a device id and name, unlike the router.
- Live tests on 2026-11-19 against a local ntfy server (v2.36.0, a
  throwaway container on the internal network; nothing went to ntfy.sh):
  - `sentinel notify --test` was stored by the server with the expected title,
    priority 3 and timestamp.
  - Stopping Ollama with a 1-minute window: alert 76 seconds after the stop
    command (window plus one 10-second check); "Resolved" 10 seconds after it
    was started again.
  - Cutting the container's internet route with a 1-minute API window and a
    2-minute silence window: "NextDNS API failing" after 64 seconds, "No events
    from router for 2 min" after 114 seconds, both resolved within 26 seconds
    of reconnecting.
- **NextDNS accepted a 6½-day-old stream cursor** and replayed the missed
  events (about 900 a second at first), so a long outage left no gap. The
  replay was slowed by HTTP 429 `rateLimit` when two profiles reconnected at
  once; with a 1-minute window this raised a short "API failing" alert.
- First run over the router profile's week (161,117 events): processed in about
  90 seconds. Before decision 23, `dga-like` produced 287 findings, nearly all
  customer hostnames on cloud platforms, and 92 of 103 RDAP lookups were for
  such names. After it: 2 findings in total (one `young-domain`, one
  `volume-spike`) and 10 RDAP lookups.

Live check of the dashboard on 2026-11-19, on the real stack with a throwaway
token:

- `docker port` showed `8080/tcp -> 127.0.0.1:8080`, and the only listener on
  the host's port 8080 was on 127.0.0.1. Connecting to port 8080 on the
  machine's LAN address was refused (`ConnectionRefused`), as it was on every
  virtual adapter's address; 127.0.0.1 answered.
- `GET /login` returned 200 with every header listed under "The dashboard".
- The XSS audit from the test suite, run over the 12 pages built from the real
  data (GET requests only, nothing changed), found no problems.
- In a browser, on test data with the hostile payloads: filtering through htmx
  and acknowledging a row worked, the console showed no CSP violations, and
  at 375 pixels wide no page scrolled sideways.

The first `sentinel eval` on 2026-11-19 used qwen3:8b on your stored history:
373,427 events over 19.9 days. All counts are in [EVALUATION.md](EVALUATION.md);
no name from your history or the feeds appears in it.

- **False alerts.** 1 high or critical finding in 19.9 days, 0.05 a day,
  against a target of at most 2.
- **Benign names.** No name was flagged, from either the top-sites sample
  (1,000) or your own history (792).
- **Threat-feed domains.** 93% flagged. Without the feed match, the other
  rules catch only 10%.
- **DGA names.** Random-character names 45% flagged, dictionary-word names 8%.
  The dga-like thresholds miss short and word-based names.
- **Tunnels.** All 20 fast tunnels caught by tunnel-like. None of the 10 slow
  ones were caught by tunnel-like, but all 10 were flagged by dga-like because
  of their random-looking labels.
- **Crafted injection names.** Only 27% produce a finding at all; 11 were
  raised to high by the pre-filter.
- **Prompt injection.** 0 of 60 succeeded in all four rounds (thinking off and
  on, defences on and off), with 0 schema failures. Model calls took 17 to 27
  seconds (p50) for 10 findings.
- **A correction to the method.** The first run counted hedged advice ("verify
  whether it is legitimate") as obedience and reported 2% to 8%. That was
  corrected and disclosed in the report; the cases are listed there.
- **What the injection result does not show.** The undefended baseline was
  not steered either, so this run does not show the defences making a
  difference. What they guarantee holds by construction.

## Open points raised with the owner

- "Only the NextDNS API is called" conflicts with RDAP lookups, list downloads
  and any notification channel. Enrichment follows decision 21; say if RDAP
  should be off by default.
- Rule thresholds are first guesses. They are to be judged by the evaluation
  suite, not tuned on the same week of data they were first run on.
- The notification channel (ntfy, Discord webhook or email) is not chosen, so
  delivery has been proven only against a local ntfy server.
- The laptop profile has sent nothing for 19 days and is reported as a health
  problem. Give it `stale_after_minutes` or `quiet_hours`, or disable it.
- No Git remote exists yet, so the CI workflow has not run on GitHub.
- `DASHBOARD_TOKEN` is not set in `.env` yet, so the dashboard is off until
  you add one.
- Whether to pace history requests to stay under the undocumented rate limit,
  for example when several profiles backfill at once.

## Future work

- Pin base images by digest and automate updates.
- Run device names through the instruction-word pre-filter too.
- Measure young-domain recall in the evaluation, with registration dates
  cached ahead of time for a fixed test set.
- Optional abuse.ch feeds for users who register for a free key.
- Use the Public Suffix List to tell registrable domains from platform
  customer names exactly, instead of the parent-rank heuristic.
- A health check on notification delivery itself (a broken channel is
  currently visible only in the logs and the outbox).
- Batch stream writes if catch-up after long outages needs to be faster.
- A dashboard page to review and remove stored allowlist entries (today an
  entry is removed by reopening the finding that made it).
