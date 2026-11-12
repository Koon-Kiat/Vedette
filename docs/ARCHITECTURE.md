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
| Storage | `src/sentinel/storage/` | Done for events, collector state, findings and reference data: SQLite (WAL), Alembic migrations |
| Collector | `src/sentinel/pipeline/collector.py` | Done: backfill, stream, resume, gap-fill |
| Enrichment | `src/sentinel/enrich/` | Done: first-seen, popularity, domain age (RDAP), threat feeds, lexical features |
| Rules | `src/sentinel/rules/` | Done: eight declarative rules, allowlist, deterministic engine |
| Enricher and rule workers | `src/sentinel/pipeline/processor.py` | Done |
| Defanging | `src/sentinel/notify/defang.py` | Done: used by the CLI now, by notifications later |
| LLM analyst | `src/sentinel/llm/`, `src/sentinel/pipeline/analyst.py` | Done: Ollama client, schema, guards, cache, template fallback |
| Pipeline runner | `src/sentinel/pipeline/runner.py` | Runs collector, enricher, rule engine and analyst; other stages are idle placeholders |
| CLI | `src/sentinel/cli.py` | `sentinel run`, `sentinel findings`, `sentinel import`, `sentinel --version` |
| Notifier, health, dashboard | `src/sentinel/*/` | Not started |

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

## Containers

| Service | Purpose | Network | Hardening |
| --- | --- | --- | --- |
| `sentinel` | The pipeline | `egress` (to api.nextdns.io) and `llm` | uid 10001, read-only root filesystem, all capabilities dropped, `no-new-privileges`, no published ports |
| `ollama` | Local model server with GPU | `llm` only (internal: no internet, no host port) | all capabilities dropped, `no-new-privileges`; still runs as root (see Decisions) |
| `ollama-pull` | One-shot model download (`setup` profile) | `egress` | all capabilities dropped, `no-new-privileges` |
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
10. **Ollama still runs as root.** The official image expects it. Capabilities
    are dropped and `no-new-privileges` is set, and GPU inference was confirmed
    to work that way. Running it as a non-root user with a read-only root
    filesystem is deferred to the hardening work.
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
20. **No `sentinel backfill` command yet.** `sentinel run` backfills
    automatically; a manual command is left for the CLI work.

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
27. **The allowlist is configuration only for now.** "Mark benign" from the CLI
    or dashboard, which adds to it, comes with those features.
28. **The instruction-token pre-filter is not built yet.** It belongs with the
    prompt-injection hardening of the LLM stage.

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
- Behaviour of an expired stream id is still unobserved.

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
- First run over the router profile's week (161,117 events): processed in about
  90 seconds. Before decision 23, `dga-like` produced 287 findings, nearly all
  customer hostnames on cloud platforms, and 92 of 103 RDAP lookups were for
  such names. After it: 2 findings in total (one `young-domain`, one
  `volume-spike`) and 10 RDAP lookups.

## Open points raised with the owner

- "Only the NextDNS API is called" conflicts with RDAP lookups, list downloads
  and any notification channel. Enrichment follows decision 21; say if RDAP
  should be off by default.
- Rule thresholds are first guesses. They are to be judged by the evaluation
  suite, not tuned on the same week of data they were first run on.
- The notification channel (ntfy, Discord webhook or email) is not chosen.
- No Git remote exists yet, so the CI workflow has not run on GitHub.
- Whether to pace history requests to stay under the undocumented rate limit,
  for example when several profiles backfill at once.

## Future work

- Pin base images by digest and automate updates.
- Run Ollama as a non-root user with a read-only root filesystem.
- Optional abuse.ch feeds for users who register for a free key.
- Use the Public Suffix List to tell registrable domains from platform
  customer names exactly, instead of the parent-rank heuristic.
