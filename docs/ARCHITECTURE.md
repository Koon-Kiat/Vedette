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
                           threat-intel match, label randomness, device info
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
| Enrichment | `src/vedette/enrich/` | Done: first-seen, popularity, domain age (RDAP), threat feeds |
| Rules | `src/vedette/rules/` | Done: ten declarative rules, allowlist, deterministic engine, instruction-word pre-filter |
| Enricher and rule workers | `src/vedette/pipeline/processor.py` | Done |
| Shared types and helpers | `src/vedette/shared/` | Findings, severities, verdicts, analyses, allowlist entries and outgoing messages; defanging; lexical features and feed-lookup candidates. Every package may import it; it imports none |
| LLM analyst | `src/vedette/llm/`, `src/vedette/pipeline/analyst.py` | Done: Ollama client, schema, guards, cache, template fallback |
| Notifier | `src/vedette/notify/`, `src/vedette/pipeline/notifier.py` | Done: ntfy, Discord and e-mail; outbox; quiet hours; daily digest |
| Health monitor | `src/vedette/health/` | Done: six kinds of check, alerts on change, `/healthz` |
| Pipeline runner | `src/vedette/pipeline/runner.py` | Runs all six stages, `/healthz`, the dashboard and the hourly retention purge |
| CLI | `src/vedette/cli.py` | `vedette run`, `findings`, `benign`, `backfill`, `import`, `notify --test`, `digest`, `purge`, `eval`, `--version` |
| Dashboard | `src/vedette/web/`, `src/vedette/storage/dashboard.py`, `src/vedette/storage/triage.py` | Done: eight pages, triage with an audit log, token login |
| Evaluation | `src/vedette/eval/` | Done: datasets (including popular hostnames from Cisco Umbrella), offline detection with and without the top-sites exemption, prompt-injection test with defences on and off on a held-out set, with repeats and mixed batches, history metrics, `docs/EVALUATION.md` |

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
   - lexical features of the registered label (the one left of the public
     suffix, or a platform customer's name): its length, share of digits and
     how random it reads; and the length of the subdomain in front of it.
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
   `think` off, temperature 0.1, `num_ctx` 8192 and `keep_alive` 5m. Each
   finding goes with its evidence and a context pack read from the database
   (`llm/context.py`): the device's age and usual queries an hour, the
   domain's top-sites band, age, feeds, platform flag and spread across
   devices, the names the device looked up within five minutes, its other
   findings within the hour, and how earlier findings like it were triaged.
   The system message adds two worked examples and the analyst notes of the
   rules in the request: harmless look-alikes to rule out and checks worth
   suggesting, from `rules.yaml`. The answer must parse into the schema or it
   is discarded whole. An invalid or incomplete answer is retried once.
3. **Template.** Text built from the rule's own description and the defanged
   target, at the rule's floor, marked as not written by the model.

If Ollama cannot be reached, nothing is stored and the worker retries with
backoff (5 seconds up to 5 minutes). Findings exist and are listed regardless.

### Prompt-injection defences in this stage

| Defence | Where it is enforced |
| --- | --- |
| A name never vouches for itself | `echoed_vouching` in `llm/guards.py`: an answer using a vouching word (benign, false positive, verified, trusted, ignore) that the finding's own names use is discarded for the template, in code |
| Rules own severity: the model may raise priority, never lower it | `enforce_floor` in `llm/guards.py`, applied in code after validation, to cached verdicts too |
| The model cannot suppress a finding | Findings are stored before the analyst runs; it only adds an analysis |
| Untrusted strings are data, not instructions | `build_payload` in `llm/prompts.py`: they appear only as length-capped values in a JSON payload; the system prompt is fixed |
| The records around a finding are data too | `build_pack` in `llm/context.py`: the context pack travels inside the JSON payload, every part is capped, and a name holding instruction-like words is withheld |
| A device name proves nothing about its device | `MODEL_KEYS` and `SYSTEM_PROMPT` in `llm/prompts.py`: the name is sent as `device_name_self_reported`, and the prompt says it never shows ownership, history or safety. `device_name_for_model` in `llm/context.py` withholds a name that makes claims about its device, asks for the filtering to change or holds a domain, in the evidence and the context pack alike |
| Structured output only | `parse_verdicts` in `llm/schema.py`: extra fields, wrong types and free text are rejected |
| No tools | `llm/ollama.py` never sends a `tools` field; the Ollama container has no internet route |
| Safe output | `sanitize_model_text`: HTML, markdown and links removed, names defanged, length capped; applied again on display |
| Only domains it was given | `unsupported_names` in `llm/guards.py`: a domain an answer names that is not in what the model was given for that finding (a parent of a given name counts) is taken out of the text and recorded, so a crafted name cannot be carried into a neighbour's answer either |
| A harmless leaning rests on a record | `grounded_leaning` and `cited_keys` in `llm/guards.py`: only fields the finding has count as cited, and a harmless leaning that cites no record (only a name, an id or an address) is stored as unclear |

Before this stage, the rule engine's instruction-word pre-filter raises a
finding whose name carries instruction words. `vedette eval` measures how
often crafted names steer the model, with these defences on and off.

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

**Alert delivery** is a check too, read from the outbox: bad when the most
recently finished message failed, or when a message has failed three tries
in a row; "Retrying" before that. A `vedette notify --test` is recorded in
the outbox, so a good test after fixing the channel clears it.

**The heartbeat** (`health/heartbeat.py`) covers what no alert can: the
computer, Docker or Vedette being down, or the channel itself broken. When
`HEARTBEAT_URL` is set, it sends a plain GET there every
`health.heartbeat_minutes`, from the first health check on, but only while
checks are running and alert delivery is not failing. The service at that
URL (healthchecks.io, Uptime Kuma and the like) alerts when the pings stop.

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

The code is split by part of the dashboard. `web/app.py` builds the app: the
security headers, the host check, static files and the routers.
`web/routes/` holds one module per part (login, overview, charts, live,
findings, the read-only pages, error pages). What they share, the stores,
sessions, page rendering and the request dependencies `SessionDep` and
`ViewDep`, is one `Dashboard` object in `web/dashboard.py`, and the template
filters live in `web/templating.py`.

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
  90 seconds. Before customer names on platforms were told apart, `dga-like`
  produced 287 findings, nearly all
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
  and any notification channel. The list and feeds are bulk downloads matched
  locally, and RDAP is limited to allowed, unranked, recent roots and can be
  turned off (`enrich.rdap.enabled`); say if RDAP should be off by default.
- Rule thresholds are first guesses. They are to be judged by the evaluation
  suite, not tuned on the same week of data they were first run on.
- The owner's install sends to Discord, where digests have been delivered;
  ntfy has been proven only against a local ntfy server, and e-mail only in
  tests.
- Whether to pace history requests to stay under the undocumented rate limit,
  for example when several profiles backfill at once.
- A first release's image starts private on ghcr.io, even though the
  repository is public, until its package is made public on GitHub.

## Future work

- Measure how often the registry lookup finds a young domain's date in real
  use; the evaluation measures the young-domain rule with dates given.
- Optional abuse.ch feeds for users who register for a free key.
- Batch stream writes if catch-up after long outages needs to be faster.
