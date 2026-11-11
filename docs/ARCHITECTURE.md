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
| Storage | `src/sentinel/storage/` | Done for events and collector state: SQLite (WAL), Alembic migrations |
| Collector | `src/sentinel/pipeline/collector.py` | Done: backfill, stream, resume, gap-fill |
| Pipeline runner | `src/sentinel/pipeline/runner.py` | Runs the collector; other stages are idle placeholders |
| CLI | `src/sentinel/cli.py` | `sentinel run`, `sentinel --version` |
| Enricher, rules, LLM analyst, notifier, health, dashboard | `src/sentinel/*/` | Not started |

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

14. **The events table is the hand-off to the next stage, for now.** The
    collector stores events but does not yet publish them to the queue: nothing
    consumes it, so an in-memory queue would only grow (the first backfill of
    the router profile was about 160,000 events). The enricher will read stored
    events in timestamp order, which also solves history arriving newest first.
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

## Open points raised with the owner

- "Only the NextDNS API is called" conflicts with RDAP lookups, list downloads
  and any notification channel. Needs a decision before enrichment is built.
- The notification channel (ntfy, Discord webhook or email) is not chosen.
- No Git remote exists yet, so the CI workflow has not run on GitHub.
- Whether to pace history requests to stay under the undocumented rate limit,
  for example when several profiles backfill at once.

## Future work

- Pin base images by digest and automate updates.
- Run Ollama as a non-root user with a read-only root filesystem.
