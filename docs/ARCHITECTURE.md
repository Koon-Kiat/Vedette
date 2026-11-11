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
| Pipeline runner | `src/sentinel/pipeline/runner.py` | Idle placeholder stages with clean shutdown |
| CLI | `src/sentinel/cli.py` | `sentinel run`, `sentinel --version` |
| Collector, enricher, rules, LLM analyst, notifier, health, storage, dashboard | `src/sentinel/*/` | Not started |

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
2. **Only dependencies in use are declared.** `httpx`, `httpx-sse`, SQLAlchemy and
   the rest of the spec's stack are added when the code that needs them lands,
   so the audited dependency set stays as small as possible.
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
    idempotent event ids, which arrive with the collector.
13. **Base images are pinned by version tag**, not by digest
    (`python:3.14-slim`, `ollama/ollama:0.40.16`, `ghcr.io/astral-sh/uv:0.13.7`,
    `ghcr.io/gitleaks/gitleaks:v8.30.1`). Digest pinning is listed under future
    work.

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

## Open points raised with the owner

- "Only the NextDNS API is called" conflicts with RDAP lookups, list downloads
  and any notification channel. Needs a decision before enrichment is built.
- The notification channel (ntfy, Discord webhook or email) is not chosen.
- No Git remote exists yet, so the CI workflow has not run on GitHub.

## Future work

- Pin base images by digest and automate updates.
- Run Ollama as a non-root user with a read-only root filesystem.
