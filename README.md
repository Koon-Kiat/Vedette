# Vedette

A vedette is a sentry posted ahead of the outposts to watch and warn. This one
watches your NextDNS query logs: a self-hosted pipeline that flags suspicious
DNS activity with deterministic rules, uses a **local** LLM (Ollama) only to
explain and prioritise what the rules surface, and sends a daily digest plus
real-time alerts.

- **Cheap:** no paid APIs and no cloud LLM.
- **Private:** DNS history and analysis stay on your machine.
- **Hardened:** domain names are attacker-controlled text; the LLM stage is
  built to resist prompt injection, and rules alone decide whether an alert fires.

Vedette is an independent project. It is not made, endorsed or supported by
NextDNS Inc.; it reads your own account's logs through the public NextDNS API
with your API key. "NextDNS" is used here only to say which service it works
with.

## Status

Collection and detection work: `docker compose up` backfills the last 7 days
of each enabled profile's NextDNS logs into a local SQLite database, follows
the live stream, enriches every event with local context and runs ten
deterministic rules. A local model (Ollama) then explains each finding and
may raise its priority, never lower it. High and critical findings become
instant alerts, a digest is produced every morning, and a health monitor
watches the whole pipeline. Alerts go out once you choose a notification
channel; until then they are kept and listed but not sent. A dashboard on
http://127.0.0.1:8080, reachable from this computer only, shows all of it and
lets you triage findings. Old data is purged on a schedule, every container
runs as a non-root user, and `vedette eval` measures how well the rules and
the prompt-injection defences hold up
([docs/EVALUATION.md](docs/EVALUATION.md),
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)). See
[CHANGELOG.md](CHANGELOG.md) for progress and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and decisions.

## Requirements

- A NextDNS account and its API key.
- Windows 11 with WSL2 and Docker Desktop (WSL2 backend), running.
- An NVIDIA GPU with a current Windows driver, for Ollama. `docker-compose.yml`
  reserves an NVIDIA GPU for the `ollama` service, so without one that service
  does not start as configured.
- Nothing else is installed on the host: Python, uv and every tool run in Docker.

Vedette has been run only on Windows 11 with Docker Desktop. Linux with Docker
Engine and the NVIDIA Container Toolkit should work the same way, but has not
been tested.

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
   docker compose logs -f vedette
   ```

   This builds the image on your machine. To use a released image instead,
   with no build, see "Releases" below.

Stop it with `docker compose down`. Data lives in the named volumes
`vedette-data` and `ollama-models` and survives restarts.

## Configuration

- `config.yaml` holds all non-secret settings; `config.example.yaml` documents
  each one with its default.
- Any value can be overridden by an environment variable: prefix `VEDETTE_` and
  put `__` between nesting levels, for example `VEDETTE_LLM__MODEL=qwen3:8b`.
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

Enable the commit hooks once per clone. One scans staged changes for secrets
with gitleaks through Docker; the other checks the commit message with
`tools/conventions.py`, using a Python already on the host or the Dockerfile's
pinned image, so nothing is installed:

```powershell
git config core.hooksPath .githooks
```

If you already use [pre-commit](https://pre-commit.com), `.pre-commit-config.yaml`
provides the same gitleaks check.

Pull requests are titled as a Conventional Commit, the same as the squashed
commit, and their description follows `.github/pull_request_template.md`: a
summary, the changes, how they were tested, and optional notes.

Commit messages follow git's own convention: a subject, a blank line, then
a body wrapped at 72 characters, which is how `git log`, email patches and
review tools show it. Only a single word such as a URL may run over. The
commit-msg hook, the pull request checks and a check on every push to main
hold this, squash merges included. Dependabot writes its own commit bodies,
so on its pull requests only the title is checked; its squash merge on main
has the title and an empty body.

CI (`.github/workflows/ci.yml`) runs lint, types and tests on Python 3.14 and
3.15, pip-audit, gitleaks over the full history, and a build of the image
that Trivy scans for fixable high or critical vulnerabilities, on every push
and pull request and once a week, so a new advisory for a locked
dependency shows up without a push. Dependabot proposes updates every Monday
for the Python dependencies, the CI actions, the Dockerfile's base images and
the Ollama image, each once its release is 14 days old; security updates are
not delayed.

## Releases

Pushing a version tag that matches `version` in `pyproject.toml` (for example
`v0.2.0`) runs every CI check again, then publishes the image to the GitHub
Container Registry with a signed build-provenance attestation, and creates a
GitHub Release whose notes are that version's section of `CHANGELOG.md`.

To run a released image instead of building your own, add it to `.env`:

```text
VEDETTE_IMAGE=ghcr.io/koon-kiat/vedette:0.2.0
```

then:

```powershell
docker compose pull vedette
docker compose up -d
```

Leave out `--build`, which would build locally under the released name.
Check that the image was built by this repository's release workflow:

```powershell
gh attestation verify oci://ghcr.io/koon-kiat/vedette:0.2.0 --repo Koon-Kiat/Vedette
```

Only Vedette's own image is published. Ollama runs the official
`ollama/ollama` image, and the model is still downloaded by `ollama-pull`.

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
docker compose exec vedette vedette notify --test
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
  docker compose exec vedette vedette digest
  ```

- **Health messages** when a profile goes quiet (2 hours by default), NextDNS
  keeps failing (5 minutes), the local model is unreachable (5 minutes), the
  processing backlog stays high, or the disk is nearly full, and a "Resolved"
  message when it recovers (after two good checks in a row).

Every domain in a message is defanged (`example[.]com`) and never a link.
Failed deliveries are retried with backoff for up to 10 attempts. The Health
page's "Alert delivery" check turns red when a message could not be
delivered, or after three failed tries; after fixing the channel, a
successful `vedette notify --test` clears it.

### Knowing when Vedette itself stops

Vedette cannot send an alert when the computer, Docker or Vedette is down, or
when its own alert channel is broken. For that, give it a dead man's switch: a
check at a service such as [healthchecks.io](https://healthchecks.io) or a
self-hosted Uptime Kuma, which alerts you when the pings stop.

1. Create a check there with a period of 5 minutes and a grace time of about
   10, and copy its ping URL.
2. Put it in `.env` as `HEARTBEAT_URL=...`, then run `docker compose up -d`.

Vedette pings it every 5 minutes (`health.heartbeat_minutes`) while its
health checks run and alerts get out, and stops pinging when alert delivery
is failing. The ping is a plain GET with nothing in it; the URL is treated as
a secret and never logged.

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
docker compose exec vedette vedette findings
docker compose exec vedette vedette findings --min-severity high
docker compose exec vedette vedette findings --rule young-domain --limit 20
docker compose exec vedette vedette findings --json
```

Each finding shows when it was last seen, its priority, the rule, what it is
about, the profile and device, how many events triggered it, the local model's
summary, likely cause and recommended action, and the evidence. A finding the
model has not reached yet says "not analysed yet"; one the model could not
explain gets a standard explanation and says so.
Domains are printed defanged (`example[.]com`) on purpose: names in DNS logs
are attacker-controlled, so they are never shown in a form a terminal or chat
client would turn into a link. `--json` prints them raw for scripts.

## Dashboard

The dashboard stays off until it has a login token.

1. Generate a token:

   ```powershell
   docker compose run --rm --no-deps --entrypoint python vedette -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. Put it in `.env` as `DASHBOARD_TOKEN=...` (at least 24 characters), then
   restart with `docker compose up -d`.
3. Open http://127.0.0.1:8080 and paste the token.

The token works like a password: anyone who has it can triage your findings.
A session lasts 12 hours (`dashboard.session_hours`) and ends when the
container restarts. After five wrong tokens within a minute, logins are
refused for a minute.

The dashboard is live: counts, the pipeline status, new findings and the
query feed update on their own while a page is open, so it can stay on a
screen all day. The dot next to Live in the menu is green while updates are
flowing. Everything it needs, fonts and chart code included, is served by
the dashboard itself; nothing is loaded from the internet. It uses the whole
width of wide and ultrawide screens: from 2,240 pixels the Overview and Live
pages set their panels side by side instead of in one long column.

**Profiles shown.** With more than one enabled profile, the switch at the
top of the menu shows all of them, or only one, on every page, chart, table
and the live feed; the browser remembers the choice. Each profile keeps its
own colour everywhere, in the order of `config.yaml` (the first teal, the
second violet), and each option shows how many findings are open on it,
updated as soon as you triage one, so nothing waits unseen on a profile you
are not looking at. Digests, Health and Evaluation always cover every
profile.

**Tables** sort by any column: click a heading, and click again to reverse.
On a finding's page, J and K move to the next and previous open finding.

The "Queries over time" charts on the Overview and Live pages follow live:
each query joins its bar as it arrives. You can work with them directly:

- **Range:** pick 30 minutes to 30 days with the buttons above the chart.
- **Zoom:** drag across the chart, or hold Ctrl and scroll. Zooming in fetches
  finer bars, down to one minute.
- **Move through time:** hold Shift and scroll or drag, or scroll sideways on
  a trackpad. A double-click, or "Back to live", returns to the present.
- **Read exact numbers:** point at a bar for its queries, blocked share,
  each profile's share and the usual level; point at a pink marker for the
  finding it stands for.
- **One profile or both:** with both shown, each profile is its own layer
  of the bars, its blocked queries darker; the checkboxes under the chart
  hide or show a layer.
- **Click through:** click a bar to list what happened then (totals,
  findings, the most looked-up domains and the latest queries); click a
  marker to open its finding.
- **Enlarge:** opens the same chart over the whole window; Esc closes it.
- **Keyboard:** focus the chart, then use the left and right arrows to move
  between bars, Enter to list one, plus and minus to zoom, Shift with the
  arrows to move through time, and 0 to go back to live.

| Page | What it shows |
| --- | --- |
| Overview | Open high and critical findings first, updated as they arrive; queries over time with findings marked on it; the latest queries as they happen; new devices and findings by priority; the last 24 hours per profile against the 7-day average |
| Live | Every DNS query as it arrives (within about a second), with a pause button, an only-blocked filter and a profile filter, above queries over time per minute |
| Findings | Every finding, filtered by profile, device, rule, minimum priority, status and day, with the triage buttons; each one opens to its explanation, evidence, cached domain facts, recent queries and history |
| Domains | Most allowed, most blocked, newly seen and recently registered domains, for 24 hours or 7 days |
| Devices | Devices seen in the last 7 days, or a note that the profile reports none |
| Allowlist | What the rules skip: the roots you marked benign, each with its finding and a Remove button, and the entries from `config.yaml` |
| Digests | Every digest that was produced, as it was sent |
| Health | Each health check, the newest event per profile, queue sizes, and the local model's calls, latency and cache hit rate |
| Evaluation | Results of the last `vedette eval` run, or how to start one |

Triage:

- **Acknowledge:** you have seen it.
- **Benign:** it is not a problem. For a domain finding (`young-domain`,
  `threat-intel-allowed`, `dga-like`, `tunnel-like`, `tunnel-slow`) the domain's root is also
  allowlisted for that profile, so those rules stop flagging it within about
  30 seconds. Findings already recorded are left as they are.
- **Reopen:** undoes either, and removes the allowlist entry that Benign added.
  To take back only the allowlist entry and leave the finding benign, use
  Remove on the Allowlist page.

Every action is recorded with its time in the finding's history. Mark a
finding benign from the command line with
`docker compose exec vedette vedette benign 42` (it asks first; add `--yes`
to skip the question).

The port is published on `127.0.0.1` only, so other machines on your network
cannot reach it. Keep it that way: never change `"127.0.0.1:8080:8080"` in
`docker-compose.yml` to `"8080:8080"`. To use another port, change both
`dashboard.port` in `config.yaml` and that line. The dashboard answers only
to the host names `127.0.0.1` and `localhost` (`dashboard.allowed_hosts`).

## What leaves your machine

- **NextDNS API:** your API key and profile ID, to read your logs.
- **Top-sites list (Tranco), the Public Suffix List and threat feeds
  (Phishing Army, CERT Polska):** plain downloads, weekly for the two lists
  and daily for the feeds. Matching happens locally, so these sites learn
  nothing about your queries.
- **RDAP:** to learn when a domain was registered, the registry is asked about
  that one root. This is limited to allowed, unranked domains seen in the last
  24 hours. Set `enrich.rdap.enabled: false` in `config.yaml` to stop it; the
  `young-domain` rule then stays silent.
- **Your notification channel, once you choose one:** alert and digest text
  (rule names, defanged domains, device names, counts, the model's summary) goes
  to ntfy, Discord or your mail server. A self-hosted ntfy server keeps it on
  your network.
- **Cisco Umbrella's popular-hostname list, only when you run `vedette eval`:**
  a plain download at most once a week, which the evaluation uses as
  known-good names. `vedette eval --offline` skips it.
- **Your heartbeat, if you set one:** an empty GET to `HEARTBEAT_URL` every few
  minutes. The service learns only that Vedette is running.

## Tuning and allowlisting

- Add known-good domains under `allowlist:` in `config.yaml`. An entry covers
  the root and its subdomains and may be limited to a `profile` or `device`.
- Or mark a domain finding benign in the dashboard or with `vedette benign`,
  which allowlists its root for that profile (see "Dashboard"). The
  dashboard's Allowlist page lists every entry and takes one back.
- To change a threshold, copy the rule's `id` and the `params` to change into
  a YAML file, mount it into the container and set `rules.file` to its path.
  The defaults are in `src/vedette/rules/rules.yaml`.

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
   docker compose exec vedette vedette import /imports/yourfile.csv --profile pc
   ```

Events the collector already has are recognised and not stored twice, so
importing the same file again adds nothing. Import before enabling a profile
if you can, so its history is evaluated in order.

To read a period of history from the API instead (for example after the
service was off for longer than the stream can catch up), run:

```powershell
docker compose exec vedette vedette backfill --days 3
docker compose exec vedette vedette backfill --profile pc --days 7
```

Events already stored are recognised and not stored twice, and the live
stream is not disturbed. `--days` may not be longer than the retention of raw
events (30 days by default). Reading many days makes many API requests.

An export is NextDNS's raw view: it includes repeat lookups that the API's
default view removes. The importer keeps A, AAAA and HTTPS queries and merges
rows that differ only by query type, but an imported period still holds more
events than a collected one (about a third more in the file this was tested
with). If the two must match exactly, set `ingest.raw: true`, which makes the
API deliver the raw view too.

## Keeping and wiping your data

Your DNS history is personal data and stays in the `vedette-data` volume, in
files only the service's own user can read. By default raw events are kept
for 30 days and findings for 180 (`retention` in `config.yaml`). Once an hour
the pipeline deletes anything older, together with what came from it: the
model's explanations, alerts and digests about it, and its triage history.
Allowlist entries you made by marking findings benign stay in force.

Delete expired data now, or everything:

```powershell
docker compose exec vedette vedette purge
docker compose stop vedette
docker compose run --rm vedette purge --all
```

`purge --all` deletes every event, finding, digest, decision and cache, and
asks first (`--yes` skips the question). When the service starts again it
reads the backfill window from NextDNS anew; to stop collecting altogether,
disable the profiles in `config.yaml` or remove `NEXTDNS_API_KEY`.

## Measuring how well it works

`vedette eval` runs known-good names (the top-sites list, 1,000 popular full
hostnames from Cisco Umbrella's list and a sample of your own history),
known-bad names (threat-feed domains, synthetic DGA names and bursts, fast,
slow and sustained tunnels, and domains with given registration dates) and a
held-out set of 315 crafted prompt-injection items (names, device names and
lists of roots, written without reading the defences) through the real rules
and the local model, with the defences on and off. A sample of those items is
also put among ordinary findings, to see whether one crafted finding changes
what the model says about the others. It also replays all of your stored history
through the rules as they are now, which shows how often each rule would fire
on your own traffic. It writes a report and fills the dashboard's Evaluation
page. The known-good names also run "as if unlisted", with their top-sites rank
removed, because the rules skip listed domains; a result that could not have
come out otherwise is labelled true by construction. Names sampled from your
history and the feeds are only counted, never printed; flagged names from the
two public lists are shown, even one a feed also lists. Apart from downloading Cisco
Umbrella's public hostname list at most once a week (`--offline` skips it), it
talks only to the local model.

```powershell
docker compose run --rm -v "${PWD}/docs:/out" vedette eval --output /out/EVALUATION.md
```

(bash: `-v "$PWD/docs:/out"`.) It takes a while: every injection round asks
the model about all 315 items, with thinking off and on, and the mixed
batches on the first model add about 70 calls per setting. `--think off`
halves that, `--no-cross` skips the mixed batches (`--cross-per-category`
sizes them), `--no-llm` skips the model entirely, `--model` (repeatable) tests
another downloaded model, and `--repeats N` runs the set N times per setting
for tighter confidence intervals.

To finish several times sooner, let Ollama answer four calls at once and send
four at a time, then put Ollama back as it was:

```powershell
$env:OLLAMA_NUM_PARALLEL=4; $env:OLLAMA_FLASH_ATTENTION=1; $env:OLLAMA_KV_CACHE_TYPE="q8_0"; docker compose up -d ollama
```

```powershell
docker compose run --rm -v "${PWD}/docs:/out" vedette eval --parallel 4 --think off --output /out/EVALUATION.md
```

```powershell
Remove-Item Env:OLLAMA_NUM_PARALLEL, Env:OLLAMA_FLASH_ATTENTION, Env:OLLAMA_KV_CACHE_TYPE; docker compose up -d ollama
```

The flash attention and 8-bit cache settings let four answers fit in 12 GB of
graphics memory; a smaller card may need `--parallel 2`.

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
docker compose exec vedette python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8081/healthz').read().decode())"
```

It returns `ok` or `degraded` with every check's result. If you change
`health.healthz_port`, change the port in the health check in
`docker-compose.yml` too.

## Reporting a security problem

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a
vulnerability.

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
  webhook deleted, bad mail password). Run `vedette notify --test` to see why.
- **`popularity_refresh_failed` or `threat_feed_refresh_failed`:** a download
  failed. The previous copy stays in use and the download is retried hourly.
  With no top-sites list at all, the `young-domain` and `dga-like` rules stay
  silent rather than guess.
- **`collector_source_unavailable` with HTTP 429:** NextDNS is rate-limiting.
  The collector backs off and recovers on its own; nothing is lost.
- **`dashboard_disabled`:** the message gives the reason, either
  `DASHBOARD_TOKEN is not set` (see "Dashboard") or
  `dashboard.enabled is false`. The rest of the pipeline runs normally.
- **`dashboard_unavailable`:** the dashboard's port is taken inside the
  container. The rest of the pipeline keeps running; change `dashboard.port`
  and the `ports` line in `docker-compose.yml` together.
- **`retention_purge_failed`:** the scheduled purge could not finish; it
  tries again an hour later. The message names the error.
- **Ollama keeps restarting with a permission error:** the model volume was
  not handed to Ollama's user. Run `docker compose up ollama-volume-owner`
  and then `docker compose up -d`.
- **"Invalid host header" in the browser:** open the dashboard as
  http://127.0.0.1:8080 or http://localhost:8080, or add the name you use to
  `dashboard.allowed_hosts`.

- **`env file .env not found` or a bind-mount error for `config.yaml`:** run the
  two `Copy-Item` commands above.
- **`could not select device driver "nvidia"`:** update the NVIDIA Windows driver
  and make sure Docker Desktop uses the WSL2 backend.
- **Docker commands fail to connect:** start Docker Desktop and wait for it to
  finish starting.
