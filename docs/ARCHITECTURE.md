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
| Enrichment | `src/vedette/enrich/` | Done: first-seen, popularity, domain age (RDAP), threat feeds |
| Rules | `src/vedette/rules/` | Done: ten declarative rules, allowlist, deterministic engine, instruction-word pre-filter |
| Enricher and rule workers | `src/vedette/pipeline/processor.py` | Done |
| Shared types and helpers | `src/vedette/shared/` | Findings, severities, verdicts, analyses, allowlist entries and outgoing messages; defanging; lexical features and feed-lookup candidates. Every package may import it; it imports none (decision 105) |
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
| A device name proves nothing about its device | `MODEL_KEYS` and `SYSTEM_PROMPT` in `llm/prompts.py`: the name is sent as `device_name_self_reported`, and the prompt says it never shows ownership, history or safety (decision 104) |
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

## Decisions

"The spec" below is the original project brief, which is not part of this
repository; a decision that departs from it says so. Where a test or a CI step
holds a decision, the decision names it, and that check is the source of truth.
Numbers never change, so a replaced decision keeps a one-line pointer. What was
tried and measured along the way is in git history and `docs/EVALUATION.md`.

1. **The repository root is the spec's project root.**
2. **Only dependencies in use are declared**, each added with the code that
   needs it, so the audited set stays small.
3. **`hatchling` builds the package**, to install the `vedette` command.
4. **`tzdata` and `pyyaml` are direct dependencies.** `python:3.14-slim` has no
   time zone database, and the config loader parses YAML itself so it can
   refuse secrets. Held by `test_time_zone_data_and_yaml_are_direct_dependencies`.
5. **Dependencies are locked with hashes.** Images and CI install with
   `uv sync --locked`, which checks every hash, and `pip-audit` reads a hashed
   export of the same lock (`.github/workflows/ci.yml`).
6. **Secrets never come from `config.yaml`**, only from the environment or a
   Docker secret. Held by `test_api_key_in_the_yaml_file_is_rejected` and
   `test_api_key_is_read_from_a_docker_secret_file`.
7. **Environment overrides use `VEDETTE_` and `__`** (`VEDETTE_LLM__MODEL`);
   lists take JSON. Unknown keys in the YAML file are errors, so a typo stops
   start-up. Held by `test_env_var_overrides_the_profile_list_with_json` and
   `test_an_unknown_key_in_the_yaml_file_is_an_error`.
8. Replaced by decision 40.
9. **Ollama has no route to the internet.** It joins only the internal `llm`
   network and publishes no port; the one-shot `ollama-pull` service fetches
   models, and `OLLAMA_NO_CLOUD` stops calls to ollama.com. Held by
   `test_ollama_has_no_route_to_the_internet`.
10. Replaced by decision 64.
11. **Secret scanning runs through Docker**: `.githooks/pre-commit` scans staged
    changes with the pinned gitleaks image and CI scans the full history, so
    nothing is installed on the host.
12. **The queue is at-least-once.** A message counts towards depth until it is
    acknowledged; restarts rely on the stored cursor and idempotent event ids.
    Held by `test_depth_counts_messages_until_they_are_acknowledged`.
13. Replaced by decision 93.
14. **The events table is the hand-off from the collector.** The enricher reads
    unprocessed events in time order from storage, so a large backfill never
    sits in memory and the hand-off survives a restart. Held by
    `test_unprocessed_events_come_back_oldest_first_up_to_the_limit`.
15. **Alembic manages the schema** and migrates at start-up. Held by
    `test_migrations_create_exactly_the_tables_the_models_describe`.
16. **One transaction per stream event**, so the cursor is stored with each
    event. Held by `test_kill_mid_stream_and_restart_leaves_no_gaps_and_no_duplicates`.
17. **Timestamps are stored as naive UTC**, since SQLite has no time zone type,
    and are aware everywhere in code. Held by
    `test_timestamps_come_back_timezone_aware`.
18. **Untrusted strings are truncated, not rejected**, so a long device name
    cannot make an event disappear; entries missing a timestamp, domain or
    status are skipped and counted. Held by
    `test_overlong_untrusted_strings_are_truncated_not_dropped` and
    `test_malformed_entries_in_a_page_are_skipped`.
19. **The stream reconnects after 5 minutes of silence**, since NextDNS documents
    no heartbeat. Held by
    `test_a_silent_stream_is_reopened_after_five_minutes_by_default`.
20. Replaced by decision 65.
21. **External lookups are what enrichment needs, and each can be turned off.**
    The spec asks that only the NextDNS API is called and also for a top-sites
    list, feeds and RDAP. The list and feeds are bulk downloads matched
    locally; RDAP reveals the root it asks about, so it is limited to allowed,
    unranked, recent roots and has `enrich.rdap.enabled`. Held by
    `test_with_rdap_disabled_nothing_is_looked_up`.
22. **Threat feeds are Phishing Army and CERT Polska by default**: both download
    without an account. Check a feed's terms before adding it. Held by
    `test_enrichment_and_rule_defaults_match_the_documented_ones`.
23. Replaced by decision 99, which keeps the parent-rank guess only until the
    Public Suffix List is downloaded.
24. **A feed limits the damage it can do.** An entry never taints its parent or
    siblings, a match on a top-1,000 root is distrusted, and a failed or empty
    download keeps the previous entries. Held by
    `test_threat_feed_matches_listed_names_and_their_subdomains`,
    `test_threat_intel_does_not_fire` and
    `test_failed_or_empty_feed_refresh_keeps_the_previous_entries`.
25. **Rule state is in memory and rebuilt from storage** at start-up, with no
    state table to keep consistent. Held by
    `test_processed_events_can_be_replayed_in_order_for_warm_up`.
26. **An unexpected error in the rule worker stops the process**, because engine
    state would no longer match storage; every other worker logs and retries
    (`run_forever` in `src/vedette/retry.py`). Held by
    `test_an_unexpected_error_in_the_rule_worker_ends_it`.
27. Replaced by decision 56.
28. Replaced by decision 61.
29. **History can also come from a log export**; real-time alerts still need
    the stream, and the file is never downloaded automatically. Held by
    `tests/unit/test_cli_import.py` and `tests/unit/test_nextdns_export.py`.
30. **Query type is part of the event id in raw mode only**, where one name's
    A, AAAA and HTTPS lookups otherwise collide. Held by
    `test_api_query_type_changes_the_id_only_in_raw_mode`.
31. **The importer does not imitate NextDNS's undocumented removal of
    repeats**, so it says every time that a file can hold more than the API
    shows. Held by
    `test_import_warns_that_a_file_holds_more_than_the_default_api_view`.
32. **One verdict per finding, many findings per call**; a missing verdict
    counts as an invalid answer for that finding only. Held by
    `test_a_finding_the_model_skipped_gets_a_template_after_one_retry`.
33. **Invalid twice means a template; unreachable means wait**, so a poison
    finding cannot loop and an outage leaves no templates behind. Held by
    `test_two_invalid_answers_fall_back_to_templates` and
    `test_ollama_being_down_does_not_stop_findings_and_is_caught_up_later`.
34. **Template fallbacks are never cached.** Held by
    `test_template_fallbacks_are_not_cached`.
35. **Model text is stored sanitised and defanged**, with only the dots inside
    names bracketed. Held by `test_model_text_is_sanitised_before_it_is_returned`
    and `tests/unit/test_properties.py`.
36. **`vedette findings --min-severity` uses the effective priority.** Held by
    `test_min_severity_uses_the_raised_priority`.
37. **Every model call is recorded** for the health page and the evaluation.
    Held by `test_model_calls_are_recorded_for_later_reporting`.
38. **The dev container joins the internal `llm` network** so `pytest --live`
    reaches the model. Held by `test_the_dev_container_can_reach_the_model`.
39. **Every message goes through a durable outbox**, so alerts survive restarts,
    every outcome is recorded, and a finding is never alerted twice. Held by
    `test_pending_alerts_survive_a_restart` and
    `test_a_fresh_critical_finding_is_queued_once`.
40. **No channel means "kept, not sent"**, so choosing a channel later does not
    flood you with old alerts. Held by
    `test_without_a_channel_alerts_are_recorded_but_not_sent`.
41. **Alerts are for fresh findings**, so a backfill or an import does not set
    off a burst of old alerts; older ones go to the digest. Held by
    `test_old_findings_go_to_the_digest_not_to_an_alert`.
42. **A high or critical finding waits briefly for the model**, so the alert can
    carry its explanation. Held by
    `test_an_unexplained_high_finding_waits_briefly_for_the_model`.
43. **The cooldown is for finding alerts only.** Health messages always report
    a change, and two good checks in a row count as recovered. Held by
    `test_a_problem_that_returns_after_a_recovery_is_reported_again` and
    `test_a_single_good_check_in_a_bad_spell_is_not_a_recovery`.
44. **Quiet hours hold messages, they do not drop them**; critical alerts and
    digests are never held. Held by
    `test_high_alerts_wait_for_quiet_hours_to_end_but_critical_ones_do_not`.
45. **Notification secrets come only from the environment or Docker secrets**,
    and a channel without its secret stops start-up. Held by
    `test_notification_secrets_in_the_yaml_file_are_rejected` and
    `test_discord_needs_a_real_webhook_url`.
46. **Plain `http` for ntfy only on the local Docker network.** Held by
    `test_ntfy_url_must_be_https_unless_the_server_is_local`.
47. **`/healthz` is a minimal standard-library server** that answers only
    `GET /healthz`. Held by `test_healthz_rejects_anything_else`.
48. **Docker health means liveness**: `/healthz` stays 200 and says `degraded`
    when a check fails, and the problem goes out by alert and digest. Held by
    `test_healthz_reports_ok_or_degraded_with_every_check`.
49. **An idle stream is not an error.** Held by
    `test_the_source_reports_idleness_only_after_the_stream_opened`.
50. **The digest is built from stored data only**, so `vedette digest` can
    preview it. Held by `tests/integration/test_digest.py`.
51. **Charts are drawn as SVG on the server**, so pages work without
    JavaScript under the strict CSP; decision 73 adds the interactive charts
    on top. Held by `tests/integration/test_web_charts.py`. (Departs from the
    spec's vendored chart library.)
52. **htmx 2.0.11 is vendored and locked down**: no `eval`, no script tags in
    swapped content, this origin only, no history cache. Held by
    `test_the_vendored_htmx_is_the_reviewed_file`.
53. **One shared token and in-memory sessions**: the dashboard has one user,
    and no session data reaches disk. Held by
    `tests/integration/test_web_auth.py`.
54. **The host name is checked, not just the address**, against DNS
    rebinding. Held by `test_an_unexpected_host_name_is_refused`.
55. **The dashboard listens on every interface inside the container**, and is
    published on `127.0.0.1` only. Held by
    `test_every_published_port_is_on_loopback`.
56. **Mark benign on a domain rule allowlists the root for that profile**;
    reopening removes the entry, and the rule worker reloads the allowlist
    within 30 seconds. Held by
    `test_marking_a_domain_finding_benign_allowlists_its_root`,
    `test_reopening_undoes_the_allowlist_entry` and
    `test_the_rule_worker_reloads_the_stored_allowlist`.
57. **Web-facing dependencies are pinned exactly** (`fastapi`, `jinja2`,
    `python-multipart`, `uvicorn`). Held by
    `test_web_facing_dependencies_are_pinned_exactly`; decision 106 holds
    their age.
58. **Less on the wire and in the logs**: no API description pages, no
    `Server` or `Date` header, no access log. Held by
    `test_framework_api_pages_are_switched_off` and
    `test_the_dashboard_serves_while_the_pipeline_runs`.
59. **`/healthz` stays separate from the dashboard**, reachable without a login
    and only on loopback. Held by `test_healthz_listens_on_loopback_only`.
60. **The database pool serves every worker and the dashboard at once.** Held
    by `test_the_pool_serves_every_worker_and_the_dashboard_at_once`.
61. **The pre-filter raises one step and never creates a finding.**
    Distinctive instruction words match anywhere in a label, common ones only
    as whole words. Held by `tests/unit/test_prefilter.py` and
    `test_a_distinctive_word_is_caught_anywhere_in_a_label`.
62. **The retention purge removes processed events and old findings with what
    hangs off them**, and keeps the first-seen index, the reference caches,
    evaluation runs and allowlist entries. Held by
    `test_the_purge_removes_only_what_is_past_retention` and
    `test_an_allowlist_entry_outlives_the_finding_that_made_it`.
63. **Owner-only files, by umask and by repair.** Held by
    `test_the_database_is_made_owner_only`.
64. **Ollama runs as uid 10002 with a read-only root filesystem**; only a
    one-shot service with `CHOWN` and `DAC_READ_SEARCH` runs as root, to own
    the model volume. Held by
    `test_ollama_runs_unprivileged_with_a_read_only_root`.
65. **`vedette backfill` adds history without moving the stream cursor**, and
    never further back than the event retention. Held by
    `test_backfill_leaves_the_stream_cursor_alone` and
    `test_backfill_will_not_read_past_the_retention`.
66. **The evaluation reuses the real enrichment and rules offline**, compares
    defences on and off, and shows sampled names only as counts. Held by
    `tests/integration/test_eval.py`.
67. **The dashboard's look** is recorded in `docs/ux/decisions.md` and
    `.impeccable/surfaces/src-vedette-web.md`.
68. **Dark only, at the owner's request.**
69. **Self-hosted fonts**, since the CSP allows no external ones. Held by
    `test_the_vendored_fonts_are_the_reviewed_files`.
70. **Server-sent events for the live feed**: one-way, reconnecting, and inside
    `connect-src 'self'`. Held by `test_the_stream_sends_new_queries_and_counters`.
71. **The live feed follows event time**, with an overlap window and the ids
    already sent. Held by `test_a_second_poll_does_not_repeat_queries`.
72. **Narrow findings tables fold**, by container query, so the decision
    buttons stay in view (`docs/ux/adaptation-narrow-window.md`).
73. **uPlot draws the interactive charts**: small, no dependencies, and no
    `eval` or inline styles under the CSP. Held by
    `test_the_vendored_uplot_is_the_reviewed_file`.
74. **The server picks the bar size**, so zooming never sends raw events.
    Held by `test_the_bar_size_follows_the_span`.
75. **Live charts add queries in the browser and re-fetch the series** to
    correct drift. This is browser code in `charts.js`, with no test.
76. **The Overview chart spans the full width.**
77. **Wide screens get more columns, not longer lines.**
78. **Our static files are versioned by content** and revalidated on each
    load. Held by `test_our_static_files_are_versioned_and_revalidated`.
79. **The dashboard was evaluated against usability heuristics**; findings and
    fixes are in `docs/ux/evaluation-dashboard.md`.
80. **CUDA's kernel cache lives in the model volume**, because the read-only
    root otherwise makes every model load recompile its GPU kernels. Held by
    `test_the_gpu_kernel_cache_lives_in_the_model_volume`.
81. **Calls to the model are sized to its context window.** Held by
    `test_calls_are_sized_to_the_context_window`.
82. **A missed first digest is made late** when the computer was off at the
    digest time. Held by
    `test_a_first_digest_missed_while_the_computer_was_off_comes_late`.
83. **Silence is not judged while a profile catches up after start-up.** Held
    by `test_silence_from_while_vedette_was_off_is_not_reported`.
84. **One profile switch for the whole dashboard**, chosen by the owner and
    recorded in `.impeccable/surfaces/src-vedette-web.md`.
85. **The project is called Vedette.** It began as "NextDNS Sentinel"; the
    owner renamed it before publishing, since the name belongs to NextDNS
    Inc. NextDNS is still named where it describes the service. Held by
    `test_the_old_project_name_is_only_in_the_rename_records`.
86. **The default time zone is UTC**, so new users elsewhere do not get the
    owner's. Held by `test_defaults_when_no_file_is_given`.
87. **Design-tool briefs and agent plans stay local**: `PRODUCT.md`,
    `DESIGN.md` and `docs/superpowers/` are git-ignored. Held by
    `test_design_and_agent_working_files_stay_local`.
88. **CI actions are pinned to a release's commit**, since a tag can move.
    Held by `test_actions_are_pinned_to_a_commit`.
89. **CI also runs weekly and builds the image**, so a new advisory or a broken
    Dockerfile shows up without a push. Held by
    `test_ci_runs_weekly_and_builds_the_image`.
90. **Dependabot waits until a release is 14 days old**; security updates skip
    the wait. Held by `test_dependabot_waits_two_weeks_for_every_ecosystem`.
91. **Releases come from a version tag**, and only after every CI check passes
    at that commit; the workflow refuses a tag that differs from the version
    in `pyproject.toml` (`.github/workflows/release.yml`). Compose builds
    locally unless `VEDETTE_IMAGE` names a release, which the settings ignore:
    `test_the_compose_image_variable_is_not_a_setting`.
92. **The public repository uses GitHub's own security checks**: private
    vulnerability reporting, Dependabot alerts, secret scanning with push
    protection, and CodeQL's default setup. These are repository settings,
    not files.
93. **Every image is pinned to a digest**; Dependabot cannot see the gitleaks
    copies, which are bumped together by hand. Held by
    `test_every_image_is_pinned_to_a_digest` and
    `test_every_copy_of_the_gitleaks_image_is_the_same`.
94. **A heartbeat for what no alert can report**: Vedette pings a dead man's
    switch while its checks run and alerts get out. Held by
    `test_the_pipeline_pings_the_heartbeat_once_checks_have_run` and
    `test_the_heartbeat_is_withheld_while_alerts_cannot_get_out`.
95. **The runtime image ships no pip and takes Debian's security fixes.** Held
    by the CI steps "The runtime image has no pip" and the Trivy scan.
96. **The dashboard's routes are modules** in `src/vedette/web/routes/`.
97. **Device names go through the pre-filter**, checked only for words with no
    business in a device name. Held by `test_everyday_device_names_are_left_alone`
    and `test_a_device_name_with_instructions_is_found`.
98. **An Allowlist page** lists stored and configured entries and removes
    stored ones. Held by `tests/integration/test_web_allowlist.py`.
99. **The Public Suffix List decides what is a platform customer name.** Held
    by `tests/unit/test_public_suffix.py` and
    `test_a_platform_suffix_is_a_private_rule_the_name_sits_under`.
100. **Two rules for patterns over time**, `tunnel-slow` and `dga-burst`, both
     starting at medium. Held by `tests/unit/test_rules_bursts.py`.
101. **The evaluation measures false alerts on names the rules do not skip**,
     and labels results that could not have come out otherwise. Held by
     `test_ranks_off_shows_what_each_rule_does_on_its_own` and
     `test_popular_hostnames_are_sampled_with_their_registered_roots`.
102. **Prompt injection is measured on a held-out set**, with repeats,
     intervals and mixed batches. Held by
     `test_the_suite_repeats_the_held_out_set_and_reports_every_part` and
     `test_a_crafted_finding_that_changes_its_neighbours_is_counted`.
103. **The pre-filter reads the roots a burst finding lists.** Held by
     `test_each_root_a_burst_lists_is_checked_as_a_domain_name`.
104. **A device name reaches the model as a self-reported label that proves
     nothing.** Held by
     `test_the_model_sees_a_device_name_marked_as_self_reported` and
     `test_the_system_prompt_says_a_device_name_proves_nothing`.
105. **Packages import only the layers below them.** Held by the import-linter
     contract in `pyproject.toml`, run in CI as `lint-imports`.
106. **Corrections become checks.** `tools/conventions.py` checks commit
     messages and pull requests, `tools/lock_age.py` holds releases added to
     the lock to 14 days old, and `tests/unit/test_repository.py` holds the
     repository's names and pins. Commit bodies are wrapped at 72 characters,
     git's own convention, rather than written one line per paragraph; every
     commit pushed to main is checked, squash merges included. Held by
     `test_a_paragraph_written_on_one_long_line_is_refused` and
     `test_every_commit_pushed_to_main_is_checked`.

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
- A first release's image starts private on ghcr.io, even though the
  repository is public, until its package is made public on GitHub.

## Future work

- Measure how often the registry lookup finds a young domain's date in real
  use; the evaluation measures the young-domain rule with dates given.
- Optional abuse.ch feeds for users who register for a free key.
- Batch stream writes if catch-up after long outages needs to be faster.
