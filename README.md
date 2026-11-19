# NextDNS Sentinel

A self-hosted pipeline that ingests NextDNS query logs, flags suspicious DNS
activity with deterministic rules, uses a **local** LLM (Ollama) only to explain
and prioritise what the rules surface, and sends a daily digest plus real-time
alerts.

- **Cheap:** no paid APIs and no cloud LLM.
- **Private:** DNS history and analysis stay on your machine.
- **Hardened:** domain names are attacker-controlled text; the LLM stage is
  built to resist prompt injection, and rules alone decide whether an alert fires.

## Status

Collection and detection work: `docker compose up` backfills the last 7 days
of each enabled profile's NextDNS logs into a local SQLite database, follows
the live stream, enriches every event with local context and runs eight
deterministic rules. A local model (Ollama) then explains each finding and
may raise its priority, never lower it. High and critical findings become
instant alerts, a digest is produced every morning, and a health monitor
watches the whole pipeline. Alerts go out once you choose a notification
channel; until then they are kept and listed but not sent. The dashboard is
not built yet. See
[CHANGELOG.md](CHANGELOG.md) for progress and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and decisions.

## Requirements

- Windows 11 with WSL2 and Docker Desktop (WSL2 backend), running.
- An NVIDIA GPU with a current Windows driver, for Ollama.
- Nothing else is installed on the host: Python, uv and every tool run in Docker.

## Quickstart (Windows 11 + Docker Desktop)

Run these in PowerShell from the repository folder.

```powershell
Copy-Item .env.example .env
Copy-Item config.example.yaml config.yaml
```

(bash: `cp .env.example .env && cp config.example.yaml config.yaml`)

1. Edit `.env` and set `NEXTDNS_API_KEY` (bottom of your NextDNS account page).
2. Edit `config.yaml` and replace `ROUTER_PROFILE_ID` with the ID shown on the
   profile's Setup page in the NextDNS dashboard.
3. Download the model once (about 5.2 GB for `qwen3:8b`):

   ```powershell
   docker compose --profile setup run --rm ollama-pull
   ```

4. Start the stack:

   ```powershell
   docker compose up --build -d
   docker compose logs -f sentinel
   ```

Stop it with `docker compose down`. Data lives in the named volumes
`sentinel-data` and `ollama-models` and survives restarts.

## Configuration

- `config.yaml` holds all non-secret settings; `config.example.yaml` documents
  each one with its default.
- Any value can be overridden by an environment variable: prefix `SENTINEL_` and
  put `__` between nesting levels, for example `SENTINEL_LLM__MODEL=qwen3:8b`.
- Secrets come only from environment variables or Docker secrets, never from
  `config.yaml`. `.env.example` lists every variable.

## Development

All tooling runs in the `dev` container:

```powershell
docker compose --profile dev build dev
docker compose --profile dev run --rm dev ruff check .
docker compose --profile dev run --rm dev ruff format --check .
docker compose --profile dev run --rm dev mypy
docker compose --profile dev run --rm dev pytest
docker compose --profile dev run --rm dev pytest --live tests/live   # real model
```

Enable the secret-scanning commit hook once per clone (it runs gitleaks through
Docker, so nothing is installed on the host):

```powershell
git config core.hooksPath .githooks
```

If you already use [pre-commit](https://pre-commit.com), `.pre-commit-config.yaml`
provides the same gitleaks check.

## Getting alerts and the daily digest

Pick one channel, put its secret in `.env`, set `notify.channel` in
`config.yaml`, then restart with `docker compose up -d`. Until a channel is
set (`channel: "none"`), every alert and digest is still recorded but nothing
is sent.

| Channel | `notify.channel` | In `.env` | In `config.yaml` |
| --- | --- | --- | --- |
| ntfy (phone app, free) | `ntfy` | `NTFY_TOPIC` (long, random; it acts as a password on ntfy.sh), optional `NTFY_TOKEN` | `notify.ntfy.url` if self-hosted |
| Discord | `discord` | `DISCORD_WEBHOOK_URL` | nothing else |
| E-mail | `email` | `SMTP_PASSWORD` | `notify.email` host, port, security, username, sender, recipients |

Check that messages arrive:

```powershell
docker compose exec sentinel sentinel notify --test
```

What you will receive:

- **Instant alerts** for high and critical findings whose last event is less
  than an hour old (older ones go to the digest only). An alert waits up to 60
  seconds for the local model's explanation. The same thing (rule, profile,
  device, domain) is not alerted again within 60 minutes.
- **Quiet hours** (23:00 to 07:00 by default): high alerts and health messages
  wait until they end; critical alerts and the digest are sent anyway.
- **The daily digest** at 08:00 local time: findings grouped and ranked, new
  devices, query volume and blocking against the 7-day average, and health.
  `docs/example-digest.txt` shows one built from test data. Preview yours at
  any time (nothing is sent or stored):

  ```powershell
  docker compose exec sentinel sentinel digest
  ```

- **Health messages** when a profile goes quiet (2 hours by default), NextDNS
  keeps failing (5 minutes), the local model is unreachable (5 minutes), the
  processing backlog stays high, or the disk is nearly full, and a "Resolved"
  message when it recovers (after two good checks in a row).

Every domain in a message is defanged (`example[.]com`) and never a link.
Failed deliveries are retried with backoff for up to 10 attempts.

A laptop or phone profile is often silent for hours. Give it its own window,
or switch the silence check off for it:

```yaml
  - id: "PC_PROFILE_ID"
    label: "pc"
    stale_after_minutes: 0         # or e.g. 720
    quiet_hours: "23:00-07:00"     # silence in these hours does not count
```

## Seeing findings

```powershell
docker compose exec sentinel sentinel findings
docker compose exec sentinel sentinel findings --min-severity high
docker compose exec sentinel sentinel findings --rule young-domain --limit 20
docker compose exec sentinel sentinel findings --json
```

Each finding shows when it was last seen, its priority, the rule, what it is
about, the profile and device, how many events triggered it, the local model's
summary, likely cause and recommended action, and the evidence. A finding the
model has not reached yet says "not analysed yet"; one the model could not
explain gets a standard explanation and says so.
Domains are printed defanged (`example[.]com`) on purpose: names in DNS logs
are attacker-controlled, so they are never shown in a form a terminal or chat
client would turn into a link. `--json` prints them raw for scripts.

## What leaves your machine

- **NextDNS API:** your API key and profile ID, to read your logs.
- **Top-sites list (Tranco) and threat feeds (Phishing Army, CERT Polska):**
  plain downloads, weekly and daily. Matching happens locally, so these sites
  learn nothing about your queries.
- **RDAP:** to learn when a domain was registered, the registry is asked about
  that one root. This is limited to allowed, unranked domains seen in the last
  24 hours. Set `enrich.rdap.enabled: false` in `config.yaml` to stop it; the
  `young-domain` rule then stays silent.
- **Your notification channel, once you choose one:** alert and digest text
  (rule names, defanged domains, device names, counts, the model's summary) goes
  to ntfy, Discord or your mail server. A self-hosted ntfy server keeps it on
  your network.

## Tuning and allowlisting

- Add known-good domains under `allowlist:` in `config.yaml`. An entry covers
  the root and its subdomains and may be limited to a `profile` or `device`.
- To change a threshold, copy the rule's `id` and the `params` to change into
  a YAML file, mount it into the container and set `rules.file` to its path.
  The defaults are in `src/sentinel/rules/rules.yaml`.

## Loading history from a log export (optional)

History normally comes from the API. You can also load a log export, the CSV
that the NextDNS dashboard's Logs page downloads, for example to bring in a
period older than the backfill window. The live stream always comes from the
API.

1. Put the file in the `imports` folder next to `docker-compose.yml`
   (git-ignored, mounted read-only into the container).
2. Make sure the profile it came from is listed in `config.yaml`.
3. Run:

   ```powershell
   docker compose exec sentinel sentinel import /imports/yourfile.csv --profile pc
   ```

Events the collector already has are recognised and not stored twice, so
importing the same file again adds nothing. Import before enabling a profile
if you can, so its history is evaluated in order.

An export is NextDNS's raw view: it includes repeat lookups that the API's
default view removes. The importer keeps A, AAAA and HTTPS queries and merges
rows that differ only by query type, but an imported period still holds more
events than a collected one (about a third more in the file this was tested
with). If the two must match exactly, set `ingest.raw: true`, which makes the
API deliver the raw view too.

## How to add a profile

Add an entry under `profiles:` in `config.yaml` with the profile's ID (shown on
its Setup page in the NextDNS dashboard), a unique `label`, and `enabled: true`,
then run `docker compose up -d` again. Each enabled profile gets its own
collector and its own 7-day backfill.

## Health endpoint

`/healthz` answers on `127.0.0.1:8081` inside the container only; it is not
published to your machine or network. Docker's health check uses it, so
`docker compose ps` shows the service as healthy while its checks are running.
To read it:

```powershell
docker compose exec sentinel python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8081/healthz').read().decode())"
```

It returns `ok` or `degraded` with every check's result. If you change
`health.healthz_port`, change the port in the health check in
`docker-compose.yml` too.

## Troubleshooting

- **`collector_idle` in the logs:** the message gives the reason, either
  `NEXTDNS_API_KEY is not set` (edit `.env`) or `no profile is enabled`
  (edit `config.yaml`). Recreate the container afterwards with
  `docker compose up -d`.
- **`collector_auth_failed`:** NextDNS rejected the API key. Fix it in `.env`;
  the collector retries every 5 minutes.
- **`collector_source_error` with HTTP 404:** the profile ID in `config.yaml`
  is wrong.
- **`analyst_ollama_unavailable`:** the local model could not be reached, or
  the model is not downloaded (run the `ollama-pull` step in the quickstart).
  Findings are still detected and listed; explanations catch up when Ollama is
  back.
- **`notify_channel_not_configured`:** no channel is set, so alerts are kept
  but not sent. See "Getting alerts and the daily digest".
- **`notification_failed`:** the channel refused a message (wrong topic,
  webhook deleted, bad mail password). Run `sentinel notify --test` to see why.
- **`popularity_refresh_failed` or `threat_feed_refresh_failed`:** a download
  failed. The previous copy stays in use and the download is retried hourly.
  With no top-sites list at all, the `young-domain` and `dga-like` rules stay
  silent rather than guess.
- **`collector_source_unavailable` with HTTP 429:** NextDNS is rate-limiting.
  The collector backs off and recovers on its own; nothing is lost.

- **`env file .env not found` or a bind-mount error for `config.yaml`:** run the
  two `Copy-Item` commands above.
- **`could not select device driver "nvidia"`:** update the NVIDIA Windows driver
  and make sure Docker Desktop uses the WSL2 backend.
- **Docker commands fail to connect:** start Docker Desktop and wait for it to
  finish starting.
