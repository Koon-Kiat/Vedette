# Architecture

Vedette is five stages joined by a queue, so each stage can restart,
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
| Configuration | `src/vedette/config.py` | Done: YAML + environment overrides + Docker secrets, validated |
| Logging | `src/vedette/log.py` | Done: JSON to stdout, secrets redacted |
| Queue interface | `src/vedette/pipeline/queue.py` | Done: `EventQueue` with an in-memory implementation |
| Event model and source interface | `src/vedette/sources/base.py` | Done: `DnsEvent`, `LogSource` |
| NextDNS source | `src/vedette/sources/nextdns.py` | Done: history paging, live stream, backoff |
| Log export reader | `src/vedette/sources/nextdns_export.py` | Done: `vedette import` loads a dashboard CSV export |
| Storage | `src/vedette/storage/` | Done for events, collector state, findings, reference data, the stored allowlist, the audit log and evaluation runs: SQLite (WAL), Alembic migrations, retention purge, owner-only files |
| Collector | `src/vedette/pipeline/collector.py` | Done: backfill, stream, resume, gap-fill |
| Enrichment | `src/vedette/enrich/` | Done: first-seen, popularity, domain age (RDAP), threat feeds, lexical features |
| Rules | `src/vedette/rules/` | Done: eight declarative rules, allowlist, deterministic engine, instruction-word pre-filter |
| Enricher and rule workers | `src/vedette/pipeline/processor.py` | Done |
| Defanging | `src/vedette/notify/defang.py` | Done: CLI, alerts and digests |
| LLM analyst | `src/vedette/llm/`, `src/vedette/pipeline/analyst.py` | Done: Ollama client, schema, guards, cache, template fallback |
| Notifier | `src/vedette/notify/`, `src/vedette/pipeline/notifier.py` | Done: ntfy, Discord and e-mail; outbox; quiet hours; daily digest |
| Health monitor | `src/vedette/health/` | Done: six kinds of check, alerts on change, `/healthz` |
| Pipeline runner | `src/vedette/pipeline/runner.py` | Runs all six stages, `/healthz`, the dashboard and the hourly retention purge |
| CLI | `src/vedette/cli.py` | `vedette run`, `findings`, `benign`, `backfill`, `import`, `notify --test`, `digest`, `purge`, `eval`, `--version` |
| Dashboard | `src/vedette/web/`, `src/vedette/storage/dashboard.py`, `src/vedette/storage/triage.py` | Done: eight pages, triage with an audit log, token login |
| Evaluation | `src/vedette/eval/` | Done: datasets, offline detection, prompt-injection test with defences on and off, history metrics, `docs/EVALUATION.md` |

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

Rules live in `src/vedette/rules/rules.yaml`: id, plain name, severity floor,
description, thresholds and evidence fields. The detector behind each id is
code. A file named by `rules.file` in the config can override any value per
rule id. The dashboard, alerts and the digest lead with the name and keep the
id beside it, the reference `vedette findings --rule` takes.

When an event has no device id, per-device rules count per profile, and the
finding records that device attribution is unavailable. Rules that compare
against history (`new-device`, `volume-spike`, `new-destination-category`) stay
quiet for the first `rules.learning_days` (3) after a profile's oldest event.

## How findings get explained

The analyst worker polls for findings without an analysis, most severe first,
and handles up to `llm.max_findings_per_batch` (20) at a time. A call to the
model is also sized so its prompt and every answer fit `num_ctx`, so a batch
with long evidence is split rather than cut short. Each finding always ends
with a valid analysis, from the first of these that applies:

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

Before this stage, the rule engine's instruction-word pre-filter raises a
finding whose name carries instruction words (decision 61). `vedette eval`
measures how often crafted names steer the model, with these defences on and
off (decision 66).

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
   queues it, in one transaction. If digests were missed while it was down,
   only the most recent is produced, late. That includes the very first one
   whenever there is data from before it, so a computer that is always off at
   the digest time still gets its digest; on an empty install the first one
   comes at the first digest time after start-up.

### Health monitor

Runs every 60 seconds. Per enabled profile: silence (no events for
`stale_after_minutes`, not counting the profile's own `quiet_hours`) and
NextDNS errors (the collector reports every success and failure; an open
stream that is simply quiet is not an error). Then: the local model (Ollama's
model list, and that the configured model is downloaded), the backlog of
events waiting for the rules, and disk space where the database lives.

After a start-up, a profile whose newest stored event predates the start is
not judged for silence until its collector has caught up (a finished
backfill, an idle stream, or a streamed event under 5 minutes old), or for at
most 10 minutes. Until then the check reads "Catching up after start-up" and
neither raises nor resolves an alert: the stored events end when Vedette
stopped, so their age says nothing about the profile.

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

### Live updates

`/live/stream` is a server-sent-event stream behind the same login.

- **What it sends.** Each second it reads a short recent window of events by
  event time and sends the ones it has not sent yet, so two profiles' writers
  arriving slightly out of order lose nothing, and a backfill or import (old
  timestamps) never floods the feed. Every five seconds it sends the counters,
  and a separate signal when the open findings change.
- **How the page uses it.** On that signal htmx re-fetches the decision table
  from `/partials/decide`. Each query is also passed to the charts, which add
  it to its bar (see below).
- **Cleaning.** Every string is cleaned and defanged on the server and sent
  as JSON with `<` escaped.
- **The browser script.** `static/live.js`, our own, allowed by
  `script-src 'self'`, writes it only with `textContent`. A test fails the
  build if the script ever uses `innerHTML`, `outerHTML`,
  `insertAdjacentHTML`, `document.write`, `eval` or `new Function`.
- **Limits.** At most 8 streams at once. A stream ends after 15 minutes (the
  browser reconnects by itself) or as soon as its session ends.

### Interactive charts

The "Queries over time" charts on the Overview and Live pages are drawn by
uPlot 1.6.32 on a canvas, from `static/charts.js`.

- **Data.** `GET /api/series?from=&to=&points=` (Unix seconds, behind the
  login) returns allowed and blocked queries per bar, the usual level per bar
  (the 7-day average) and the findings in the span. The server picks the bar
  size from the span: one minute up to one day, with at most `points` bars.
  The chart asks for about one bar per 6 pixels of its width, so a wide
  screen gets finer bars; the server holds `points` between 24 and 480 (240
  when it is not given) and fetches again when a resize changes it by more
  than a fifth. The span is at most 31 days and never reaches past now, which
  bounds the cost of a request. Times or bar counts that do not parse as whole
  numbers get a 422.
- **Zooming and moving.** Each change of view fetches the series for the new
  span after a short pause, so zooming in brings finer bars.
- **Following live.** While a chart shows the present, each query from the
  live stream is added to its bar at once, the view slides on as time passes,
  and the series is fetched again every 30 seconds to 5 minutes (half a bar)
  so the bars stay exact. Queries the stream delivered after the server
  counted are added again on top of each fetch.
- **What happened in a period.** A click on a bar (or Enter on the keyboard)
  loads `GET /partials/window?from=&to=`, a server-rendered partial swapped in
  by htmx: totals, findings, the ten most looked-up roots and the latest 40
  queries, all escaped and defanged like any page.
- **Enlarge** moves the same chart into a native modal `<dialog>`, so focus,
  Esc and the backdrop come from the browser.
- **Without JavaScript** the server-drawn chart that the canvas replaces
  stays in place.
- **Safety.** The vendored files are checked by SHA-256, as for htmx and the
  fonts. uPlot sets sizes and positions through `element.style`, which the
  CSP allows; it writes no `style` attributes, HTML or code. `charts.js`
  writes text only with `textContent` and draws only finding numbers on the
  canvas. Tests fail the build if either of our scripts uses an HTML-writing
  call or `cssText`, and if `charts.js` builds a request or link from anything
  but numbers it has checked.

### Profiles shown

The rail's switch chooses which profiles every page shows: all of them, or
one. `GET /scope?to=<all|profile id>&next=<path>` stores the choice in a
`vedette_scope` cookie (`HttpOnly`, `SameSite=Strict`, a year) and redirects
back; `next` goes through the same check as every other redirect, so it never
leaves the dashboard, and an unknown profile gets a 422. A plain link does it,
so it works without JavaScript; a cross-site request carries no session
(`SameSite=Strict`) and lands on the login page.

Each request builds its reads for the chosen profiles: the dashboard's
queries already take their profile list when they are created, so the
Overview, the charts and `/api/series`, the list under a chart, the Live page
and its stream, Findings, Domains and Devices all follow the switch. Some
things stay whole on purpose:

- **The rail** counts open findings for every profile, and each option of
  the switch shows its own, so a problem on a profile not shown is still in
  sight. The live stream's open count follows the rail. A triage action's
  response carries every count in an `HX-Trigger` event
  (`vedette-counts`), so the rail and the switch change at once rather than
  at the next five-second tick.
- **A finding's page** is looked up across every profile, so a link from an
  alert or a digest always opens; its next and previous links follow the
  switch.
- **Digests, Health and Evaluation** describe the whole pipeline and say so
  in their title block.

Each profile has a layer ink, by its position in the configuration
(`layer-1`, `layer-2`, ...), used for it everywhere: the switch, tables, the
live feed and the charts. `/api/series` returns `layers`, one per profile
shown, with its own allowed and blocked counts, besides the totals.

### Controls

`static/ui.js` adds the dashboard's own controls on top of markup that works
without it:

- **Select.** A native `<select data-ui="select">` becomes a button and a
  listbox (`role="listbox"`, `aria-activedescendant`, arrows, Home, End,
  type-ahead, Esc). The native select stays in the form, holds the value and
  fires `change`, so the htmx filters work unchanged; without the script it
  is a styled native select and a Filter button.
- **Sorting.** Every `table.sortable` gets a button in each heading and
  `aria-sort`. Cells may carry `data-sort` (epoch seconds, a priority's rank)
  so times and priorities sort by value; numbers sort as numbers. A table
  that htmx refreshes (the decisions on the Overview) keeps its sort.
- **Confirm.** htmx's `hx-confirm` opens a native `<dialog>` drawn by the
  dashboard instead of `window.confirm`. Its title comes from the trigger's
  `data-confirm-title`, its question from a `<template class="confirm-body">`
  in the form when there is one (so a domain keeps its outside-name
  marking) and otherwise from the `hx-confirm` text, and focus starts on
  Cancel. The action button repeats the action's name.
- **Keys.** On a finding's page, J and K follow the next and previous open
  finding links.

The same test that guards `live.js` and `charts.js` fails the build if
`ui.js` uses an HTML-writing call or `cssText`. Checkboxes and the switch are
drawn in CSS beside a real input, which keeps the keyboard and screen-reader
behaviour of the input itself.

### Fonts

Mona Sans (variable weight and width) and JetBrains Mono (upright and italic)
are served from `static/fonts/`: the latin subsets of `@fontsource-variable`
5.3.0 under the SIL Open Font License, with the licence files beside them. A
test checks each file's SHA-256, as for htmx.

## Containers

| Service | Purpose | Network | Hardening |
| --- | --- | --- | --- |
| `vedette` | The pipeline and the dashboard | `egress` (to api.nextdns.io) and `llm` | uid 10001, read-only root filesystem, all capabilities dropped, `no-new-privileges`; one published port, the dashboard on `127.0.0.1:8080` |
| `ollama` | Local model server with GPU | `llm` only (internal: no internet, no host port) | uid 10002, read-only root filesystem, all capabilities dropped, `no-new-privileges` |
| `ollama-volume-owner` | One-shot: hands the model volume to uid 10002 before Ollama starts | none | root with only `CHOWN` and `DAC_READ_SEARCH`, read-only root filesystem, `no-new-privileges` |
| `ollama-pull` | One-shot model download (`setup` profile) | `egress` | uid 10002, read-only root filesystem, all capabilities dropped, `no-new-privileges` |
| `dev` | Lint, type-check, tests (`dev` profile) | `egress` | Development only, never deployed |

## Decisions

"The spec" below is the original project brief, which is not part of this
repository. Each decision that departs from it says so.

1. **Repository root is this folder.** The spec's project tree maps onto
   the repository root.
2. **Only dependencies in use are declared.** Each part of the spec's stack is
   added when the code that needs it lands, so the audited dependency set stays
   as small as possible.
3. **`hatchling` builds the package.** A build backend is required to install
   the `vedette` console script; hatchling is small and widely used.
4. **`tzdata` and `pyyaml` are direct dependencies.** `python:3.14-slim` has no
   system time zone database, and the config loader parses YAML itself so it
   can refuse secrets placed in the file.
5. **Dependencies are pinned with hashes in `uv.lock`.** Images install with
   `uv sync --locked`, which verifies every hash. `pip-audit` runs against a
   hashed export of the same lock file.
6. **Secrets never come from `config.yaml`.** The loader rejects
   `nextdns_api_key` in YAML outright. `NEXTDNS_API_KEY` is read from the
   environment or from a Docker secret of the same name.
7. **Environment overrides use `VEDETTE_` and `__`.** For example
   `VEDETTE_LLM__MODEL`. Lists take JSON. Unknown keys in the YAML file are
   errors so that typos surface at start-up.
8. **The notification channel is undecided.** `notify.channel` is kept as free
   text with the placeholder `NOTIFY_CHANNEL` and is not validated until the
   notifier is built. (Decision 40 replaces this.)
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
    `src/vedette/storage/migrations` and run at start-up over a synchronous
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
20. **`vedette run` backfills automatically**; the manual `vedette backfill`
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
    `vedette import` loads the dashboard's CSV export for a profile. It is an
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
36. **`vedette findings --min-severity` uses the effective priority**: the
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
    still appear in `vedette findings` and in the digest.
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
    health results), so `vedette digest` can preview it from the command line,
    and the archive keeps both the text as sent and the numbers as JSON.

51. **The chart is server-drawn SVG, not a chart library.** This departs from
    the spec, which asks for one small vendored chart library. The dashboard
    has a single chart, queries per hour as stacked bars, and under 100 lines
    of Python draw it as SVG with the bars in the markup. That adds no
    third-party JavaScript to review, pin and keep updated; the data never
    passes through JavaScript or inline JSON; it works under the strict CSP
    without exceptions; and it renders with JavaScript off. A library is worth
    adding if the dashboard needs interactive charts. (It did: decision 73
    adds one, and this drawing stays as what pages show without JavaScript.)
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
63. **Owner-only files by umask and by repair.** `vedette` sets umask 077
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
65. **`vedette backfill` adds history without touching the stream.** It reads
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
    - **Defences off.** A naive analyst kept only in `vedette/eval/`: names
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
    from outside. It was chosen from a design round and reviewed. At first
    it used the system font stack, because no font download had been
    approved (decision 69 replaces that).
68. **Dark only, at the owner's request.** The world became the night chart:
    a navy ground (never black), a darker rail, layered navy surfaces,
    severity as tinted chips, and magenta still kept for attention and
    decisions. There is no light theme.
69. **Self-hosted fonts.** The owner chose Mona Sans and JetBrains Mono and
    approved the download. They are served by the dashboard itself, because
    the strict CSP allows no external fonts. Only the latin subset is shipped:
    about 181 KB, with the interface face preloaded.
70. **Server-sent events for the live feed**, not WebSockets or htmx polling.
    The feed is one-way, the browser reconnects on its own, it works under
    `connect-src 'self'`, and it needs no extra library. Small server-rendered
    partials (refetched by htmx) keep tables in one template, so the live view
    and a page reload can never disagree.
71. **The live feed follows event time.** A short overlap window plus a record
    of ids already sent is simpler and more robust than a write-order cursor;
    the feed is for what is happening now, not for history.
72. **Narrow findings tables fold.** When the table itself is under 1,200
    pixels wide (a container query, so it covers 1,280-pixel laptops and
    narrower board columns as well as small windows), the number, rule,
    device, last-seen time and event count move into one line under the
    domain, so the decision buttons stay in view. Phones show each finding as
    a card. (At first the fold followed the window, from 641 to 1,180 pixels,
    and a 1,280-pixel laptop pushed the buttons out of view.)
73. **uPlot for the interactive charts.** The owner asked for charts that zoom,
    move through time, enlarge and click through, and approved the download.
    uPlot is about 51 KB, has no dependencies, draws on a canvas so thousands
    of bars stay fast, is MIT-licensed, and works under the strict CSP: it
    needs no `eval`, no inline `<style>` and no `style` attributes. Larger
    chart libraries were not needed for bar series.
74. **The server picks the bar size.** The browser asks for a span and how
    many bars its width suits; the server answers with at most that many (24
    to 480), from one minute to one day. Zooming therefore brings finer bars
    without the browser ever holding raw events, and every request costs one
    grouped query.
75. **Live charts add queries in the browser and check against the server.**
    Each query from the live stream joins its bar at once, and the series is
    fetched again every half bar (30 seconds to 5 minutes) to correct any
    drift, rather than re-fetching on every query.
76. **The Overview chart spans the full width.** An interactive chart needs
    the room, and the list of what happened in a period opens beneath it.
    "Right now" moved next to "New devices and findings".
77. **Wide screens get more columns, not longer lines.** The owner uses an
    ultrawide screen. The main column fills up to 3,200 pixels (a 3,440-pixel
    display less the rail) instead of stopping at 1,320, and from 2,240
    pixels the pages recompose. The Overview becomes two columns (decisions
    and the chart beside the live and daily panels), the Live page sets the
    feed beside the chart, Domains puts its four lists in one row, and a
    finding's page splits its main column. The breakpoint is where the
    findings table still shows every column in two thirds of the width;
    below it the layouts are as before.
78. **Our static files are versioned by content.** `style.css`, `live.js` and
    `charts.js` are linked as `?v=` plus the first 12 hex digits of their
    SHA-256, and every static response says `Cache-Control: no-cache`, so the
    browser checks it on each load (a 304 on this machine). Without it, a
    browser reused a day-old stylesheet with new pages after an upgrade and
    the layout broke; a hard reload did not clear it. Vendored files already
    carry their version in the file name.
79. **The dashboard was evaluated against usability heuristics** on the
    owner's real data, read-only, with triage actions tried on synthetic data.
    The findings and what was fixed are in `docs/ux/evaluation-dashboard.md`;
    the project context and the decisions made along the way sit beside it.
80. **CUDA's kernel cache lives in the model volume.** Measured on the owner's
    RTX 4070 Ti: with the root filesystem read-only (decision 64), CUDA could
    not write its default cache in `~/.nv`, so the GPU kernels were compiled
    again every time the model loaded. A call to a model that had unloaded
    took 48 to 60 seconds (load 23 to 35 s, a 460-token prompt 16 s, the
    answer at 14 tokens a second); since findings are rare, nearly every real
    call was such a call. With `CUDA_CACHE_PATH` in the volume (about 24 MB,
    1 GiB allowed), the same call takes 4.2 seconds while the model file is
    still in the operating system's memory (load 2.1 s, prompt 0.2 s, 73
    tokens a second), and a warm one 1.7 seconds. After hours idle, the first
    real call took 17 seconds: the load took 14 s, almost all of it reading
    the 5.2 GB weights back from disk, which no cache setting avoids; the
    prompt still took 0.3 s and the answer ran at 76 tokens a second. The
    model, its weights and its answers are unchanged; only compiled GPU code
    is kept. A high or critical alert now gets its explanation well inside the
    60 seconds it waits for one. `keep_alive` stays at 5 minutes, since even a
    cold call is cheap enough and the GPU memory is free between findings.
81. **Calls to the model are sized to its context window.** Measured on
    `qwen3:8b`: about 3 payload characters per token and about 130 answer
    tokens per finding, so a full batch of 20 ordinary findings uses about
    6,900 of 8,192 tokens. Long evidence (up to 20 keys, lists of ten
    200-character strings, 256-character names) could pass the window, and
    Ollama would then cut the prompt. Each call is now filled while an
    estimate (2.5 characters a token, 200 answer tokens per finding, a tenth
    of the window spare) fits. Ordinary batches are unaffected. The
    evaluation suite keeps its fixed batches, so its injection results stay
    comparable.
82. **The first digest no longer needs the service running at the digest
    time.** It used to come only at the first digest time after start-up.
    The owner's computer is off overnight and starts after 08:00, so after
    nine days of data no digest had been made. Now, while none exists, the
    latest one is produced late when stored events reach back before it.
83. **Silence is not judged while a profile catches up after start-up.**
    Twice in one week a morning start raised "No events from router for
    13 h" and its "Resolved" two minutes later: the first check ran before
    the collector had read the night's events. With a channel set, that is
    two false messages per profile on most mornings. The collector now
    reports when it has caught up; the check waits for that for at most 10
    minutes, and a problem announced before the restart is neither repeated
    nor resolved meanwhile.
84. **The dashboard became "the drawing set", with one profile switch.** The
    owner asked for a more professional and futuristic look, a way to see
    router, pc or both on every chart, sortable headings and controls of the
    dashboard's own. The world was chosen from a deal of directions, recorded
    with its reasons in `.impeccable/surfaces/src-vedette-web.md`. Profiles became layers with their own inks
    because that one idea answers the request for separation everywhere at
    once. The switch is global and remembered, not one control per panel, as
    the owner chose; its options carry open counts so scoping never hides a
    problem. Sorting runs in the browser on the rows shown, since every table
    shows all its rows (findings at most 200), and the server's order stays
    the default. Dark only and the inked decisions were kept at the owner's
    request.
85. **The project is called Vedette.** It began as "NextDNS Sentinel". Ahead of
    publishing the repository, the owner chose a name that does not use
    NextDNS's: the name belongs to NextDNS Inc., whose terms say nothing about
    third parties using it, and "DNS Sentinel" was ruled out because a
    commercial DNS-analytics product called DNSentinel exists. A vedette is a
    mounted sentry posted ahead of the outposts. Everything was renamed to
    match: the command, the Python package and module, the `VEDETTE_`
    settings prefix, the cookies and the Docker names. NextDNS is still named
    where it describes the service Vedette reads, such as `NEXTDNS_API_KEY`
    and the README's note that the project is independent.
86. **The default time zone is UTC.** The spec set Asia/Singapore, the owner's
    zone, which new users elsewhere would get without noticing: digests and
    quiet hours an hour or more off. `config.example.yaml` asks for an IANA
    zone. Tests that need a fixed zone still name Asia/Singapore themselves.
87. **The design tools' briefs stay local.** `PRODUCT.md` and `DESIGN.md` are
    read by the Impeccable and Intent design tools and are git-ignored, at
    the owner's request.
88. **CI actions are pinned to a release's commit.** A tag can be moved to
    other code; a commit cannot. Each `uses:` line names the commit and, in a
    comment, the release (`actions/checkout` v7.0.1,
    `astral-sh/setup-uv` v10.3.3). The first run on GitHub failed to start
    because `setup-uv@v10` named a tag that does not exist: setup-uv
    publishes exact releases only. Base images are still pinned by tag
    (decision 13). With the pinned actions, CI passed on GitHub on
    2026-11-21: lint, types and tests on Python 3.14 and 3.15, pip-audit
    and gitleaks.
89. **CI also runs weekly and builds the image.** A new advisory for a locked
    dependency shows up on a Monday without a push, and a change that breaks
    the Dockerfile fails a pull request rather than the release.
90. **Dependabot proposes updates weekly, once a release is 14 days old.**
    The same two-week rule as for web dependencies (decision 57), applied
    through Dependabot's cooldown to the Python lock, the CI actions, the
    Dockerfile's base images and the Ollama image. Security updates skip the
    wait. Minor and patch updates come grouped, one pull request per
    ecosystem; a major update comes alone.
91. **Releases come from a version tag.** `.github/workflows/release.yml`
    runs on a `v*.*.*` tag. It first calls the CI workflow, so nothing is
    published unless every check passes at that commit. It then refuses a
    tag that differs from `version` in `pyproject.toml`, or a version with
    no `## <version>` section in `CHANGELOG.md`. Only then does it push the
    `runtime` image to `ghcr.io/<owner>/vedette` (the version, `major.minor`
    and `latest`) with a build-provenance attestation that `gh attestation
    verify` checks, and create the GitHub Release from that changelog
    section. Started by hand, it builds the image and publishes nothing. The
    image is for `linux/amd64` only, since Ollama needs an NVIDIA GPU here.
    Compose keeps building locally unless `VEDETTE_IMAGE` names a released
    image. That variable reaches the container through `.env` too, and the
    settings loader ignores it; a test holds that.

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
  - `vedette notify --test` was stored by the server with the expected title,
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

The first `vedette eval` on 2026-11-19 used qwen3:8b on your stored history:
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
- The owner's install sends to Discord, where digests have been delivered;
  ntfy has been proven only against a local ntfy server, and e-mail only in
  tests.
- Whether to pace history requests to stay under the undocumented rate limit,
  for example when several profiles backfill at once.
- Settings to turn on once the repository is public, where they need no paid
  licence: private vulnerability reporting (`SECURITY.md` points to it),
  Dependabot alerts and security updates, secret scanning with push
  protection, and CodeQL code scanning in its default setup (Python,
  JavaScript and the workflows). A first release's image is private until
  its package is made public as well.

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
