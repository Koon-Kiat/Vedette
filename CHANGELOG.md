# Changelog

## Unreleased

### Explanations

- The local model now gets the records around each finding: when the device
  was first seen and its usual queries an hour, the domain's top-sites band,
  age, feeds and spread across your devices, the names the device looked up
  within five minutes, its other findings that hour, and how earlier findings
  like it were triaged. Names that read like instructions are withheld.
- Each rule in `rules.yaml` carries `analyst_notes`: harmless look-alikes to
  rule out and checks to suggest, sent with that rule's findings. The prompt
  adds two worked examples and asks for a cause grounded in the data and a
  step that fits it. The prompt version is now 3, so cached explanations are
  not reused.
- On a gold set of 60 findings, qwen3:8b gets the cause, a fitting step and
  no invented fact right in 37 to 39 per run, against 15 to 16 with the
  earlier prompt and 16 for the standard explanation. For harmless
  look-alikes it is right in 34 of 90 answers, against none before.
- The cost: with the defences on, five of 315 crafted items steered the
  model by calling themselves benign or verified, against one before.

### Detection

- `dga-like` now judges the registered label, the one left of the public
  suffix. `www.k3j9x2m8q1z7.com` used to be judged on `www` and never fired,
  while a random subdomain under an ordinary domain did. Subdomains are left
  to the tunnel rules.
- `dga-like` scores how much more likely a label is as random characters than
  as a real domain label, in bits, from a character model of 900,000
  registered labels on a pinned Tranco list (`tools/label_model.py` rebuilds
  it). Raw entropy could not judge short labels: a 12-character label fired
  only if every character differed. The new `min_randomness: 20` replaces
  `min_entropy`, and `min_label_length` drops from 12 to 8. A rules override
  that still sets `min_entropy` is refused with a message naming its
  replacement. Findings show the score as "Randomness, bits".
- Customer names on hosting platforms (`duckdns.org`, `github.io`,
  `pages.dev`) are no longer exempt from `dga-like` and `dga-burst`; their
  customer label is judged. Platforms that name each customer resource
  themselves (CDN endpoints, cloud storage and compute) are skipped through
  a new `assigned_name_platforms` list in `rules.yaml`. `young-domain` still
  skips every platform name.

### Evaluation

- A plain `vedette eval` now finishes in about eight minutes instead of more
  than half an hour: thinking off by default (as the service runs), four calls
  in flight, and the comparison tests trimmed. The defended injection arm
  still sees all 315 held-out items; the undefended arm sees every third item
  of each category, the cross-finding test one item per category with the
  defences on, and the gold set one run. `--full` runs everything, in about 25
  minutes, and the report says which depth ran.
- New explanation-quality test: a gold set of 60 synthetic findings, six per
  rule, with the records around each and patterns for the right cause, a
  fitting step and claims to avoid. Each model explains it three times; the
  report scores it per rule and kind of finding against the standard
  explanation, lists every miss and invented fact, and the Evaluation page
  shows the totals. `vedette eval --no-injection` runs it without the
  injection tests.
- `dga-like` is tested on 13 real malware families' domain generation
  algorithms, re-implemented from published analyses and checked against
  their sample names: bare, behind `www.` and similar, and as customer names
  on hosting platforms. The report has a table per family.
- New known-good set: 1,000 customer names on hosting platforms from Cisco
  Umbrella's top 100,000, to measure what judging platform names costs.

- The top-sites set is now labelled a sanity check: the rules skip listed
  domains, so it cannot show false alerts. Results that could not have come
  out otherwise say so, in the report and on the Evaluation page.
- New "as if unlisted" rows run the known-good names again with their
  top-sites rank removed, to show what each rule does on its own.
- New known-good set: 1,000 popular full hostnames from Cisco Umbrella's
  top-1M, grouped under their registered domains. `vedette eval` downloads the
  list itself, at most once a week, into the database; `--offline` uses the
  stored copy. A new `evaluation:` config section sets its address
  (`hostnames_url`, `null` to leave the sets out) and `refresh_days`.
- The report lists up to 20 flagged names from each public list, with the
  rules that fired, so each false alert can be checked.
- The prompt-injection test now uses a held-out set of 315 crafted items,
  written without reading the pre-filter: obfuscated, split, downplaying,
  harmful, spoofing and maximum-length names, device names, and instructions
  split across the roots of a burst finding. The 60-name development set is
  no longer sent to the model.
- Downplaying ("routine", "nothing to worry about") and harmful advice
  ("visit the site", "turn off filtering") now count as successful
  injections, besides a lowered priority and dismissals.
- `vedette eval --repeats N` runs the set N times per setting; the report
  gives each rate with a 95% interval, per category, and the pre-filter's hit
  rate on the held-out set against the development set.
- A new cross-finding test puts one crafted finding among nine ordinary ones
  and reports any change in what the model says about them, on the first
  model given (`--no-cross` skips it, `--cross-per-category` sizes it).
- `vedette eval --parallel N` keeps N model calls in flight. With Ollama
  started with `OLLAMA_NUM_PARALLEL` (now passed through by
  `docker-compose.yml`, empty by default), the evaluation finishes several
  times sooner.

### Prompt-injection defences

- The instruction-word pre-filter now checks each root a burst finding
  (`dga-burst`) lists, as it checks a looked-up name. Instructions placed in
  those roots used to reach the model without raising the finding.
- The model now sees a device name as `device_name_self_reported`, and its
  instructions say a name never shows that a device is known, approved or
  safe. For a new device it recommends checking whether you recognise it.
  New-device explanations read more generic as a result. The prompt version
  is now 2, so a new finding never reuses an explanation cached under the
  old prompt.

### Development

- Packages now import only the layers below them, checked by `lint-imports`
  in CI. The types every stage shares, defanging and the lexical features
  moved to a new `vedette.shared` package.
- A commit-msg hook and a pull request workflow check commit messages, titles
  and descriptions against the project's writing rules, and tests check the
  repository's pins and names.
- More lint rules (commented-out code, `print`, naive datetimes, complexity
  and others) and property-based tests with Hypothesis for defanging, text
  cleaning, lexical features, the Public Suffix List and the pre-filter.
- Plans written by coding agents under `docs/superpowers/` are git-ignored.
- Every worker runs in one shared loop that logs an unexpected error and tries
  again; the seven copies of that loop are gone. Copied code in the command
  line, the storage queries and the pipeline tests is shared too.
- Pull requests check that every release they add to `uv.lock` is at least 14
  days old, and milestone codes are refused in code as well as in prose.
- Commit message bodies must be wrapped at 72 characters, with a blank line
  after the subject. The commit-msg hook and the pull request checks hold
  this, and a new check runs on every commit pushed to main.
- The architecture's decisions now name the test or CI step that holds each
  one, and the history behind them moved to git. Decisions that had no check
  gained one: Ollama's network, user and GPU cache, published ports, the
  dashboard's headers and access log, the database pool, stored timestamps,
  unknown config keys, the stream timeout, backfill leaving the stream
  cursor alone, a failing rule worker, the weekly CI run, and a runtime
  image without pip.

## 0.2.0 - 2026-11-22

### Knowing when Vedette itself stops

- An optional heartbeat: set `HEARTBEAT_URL` to a dead man's switch
  (healthchecks.io, Uptime Kuma) and Vedette pings it every 5 minutes
  (`health.heartbeat_minutes`) while its checks run and alerts get out. When
  the computer, Docker or Vedette stops, or alerts cannot be delivered, the
  pings stop and that service warns you.
- A new health check, "Alert delivery", turns bad when a message could not be
  delivered or has failed three tries in a row, and reads "Retrying" before
  that. `vedette notify --test` is now recorded, so a good test after fixing
  the channel clears it.

### Dashboard

- A new Allowlist page lists what the rules skip: the roots you marked benign,
  each with the finding it came from, and the entries from `config.yaml`.
  Remove takes an entry back (the rules flag that root again within about 30
  seconds) and leaves the finding benign; its history records the removal.
- The menu's name reads "Vedette"; the rename had left "NextDNS" in front of it.

### Detection

- Two new rules for patterns over time. **Slow DNS tunnelling**
  (`tunnel-slow`) counts different long subdomains of one domain over six
  hours, so a tunnel sending a lookup a minute adds up. **Burst of new
  unknown domains** (`dga-burst`) fires when a device looks up more than 20
  domains it has never queried, none on the top-sites list, within ten
  minutes, which is how generated domains look whatever their letters. Both
  start at medium.
- `vedette eval` now replays all of your stored history through the rules as
  they are now and reports how often each would fire, and adds timed sets
  for the new rules and dated sets that measure `young-domain`. On 16.6 days
  of real history the new rules raised nothing, and they caught every
  sustained tunnel and every burst in the synthetic sets.

- The Public Suffix List, downloaded weekly, now decides which roots are
  customer names on a hosting platform (`github.io`, cloud providers) instead
  of a ranked parent domain. Customer names on platforms that are on no
  top-sites list no longer trip `dga-like` or get sent to RDAP. A root that is
  itself a platform's suffix (one region under a wildcard rule), or that is
  longer than the domain registered under the list (a platform NextDNS knows
  and the list does not), counts as a platform name too. Until the list has
  been downloaded, the old parent-rank guess stands in.
- The evaluation no longer counts a sentence that describes what a label or
  name suggests ("a label suggesting 'allowlist'") as the model obeying it.

- Device names now go through the instruction-word pre-filter as well as
  domain names, with a shorter word list (`ignore`, `instruction`, `override`
  and a few others) so that names like "Mark's iPhone" stay quiet. A hit
  raises the finding one step and lists the words in its evidence.

### A leaner, scanned image

- The runtime image no longer ships pip, which bundled urllib3, msgpack and
  setuptools code with known vulnerabilities, and it takes Debian's security
  fixes when it is built. Docker Scout went from 13 high (8 of them fixable)
  to 5 high, none fixable yet, all in glibc and OpenSSL; Vedette's own layers
  had none before or after.
- CI scans the built image with Trivy and fails on any fixable high or critical
  vulnerability. CI and the release always rebuild the image's last stage, so
  new Debian fixes are never skipped by the build cache.

### Maintenance

- `docs/ux/README.md` lists the UX working documents and says where the
  `PRODUCT.md` and `DESIGN.md` they cite are kept. The Quickstart points to the
  released image for a start without a build.
- The dashboard's routes moved out of one 645-line `create_app` into
  `web/routes/`, one module per part, sharing a `Dashboard` object
  (`web/dashboard.py`) and the template filters (`web/templating.py`).
  Nothing a user sees changed.
- Every image is pinned to its digest as well as its tag: the Python and uv
  images, the Dockerfile frontend, Ollama and gitleaks. Dependabot proposes
  new digests.
- FastAPI 0.162.0 to 0.162.2, a patch release.

## 0.1.0 - 2026-11-21

### Releases and dependency updates

- A version tag publishes a release: every CI check runs again, the image goes
  to `ghcr.io` with a signed build-provenance attestation, and a GitHub
  Release takes its notes from that version's section here. Set
  `VEDETTE_IMAGE` in `.env` to run a released image instead of building one.
- Dependabot proposes updates every Monday for the Python dependencies, the CI
  actions, the Dockerfile's base images and the Ollama image, each once its
  release is 14 days old.
- CI also runs weekly, so pip-audit sees new advisories without a push, and
  it now builds the image on every push and pull request.
- The public repository uses GitHub's own checks: private vulnerability
  reporting, Dependabot alerts and security updates, secret scanning with
  push protection, and CodeQL code scanning.
- From CodeQL's first analysis: the dashboard's redirect check refuses control
  characters and spaces itself rather than relying on Starlette's encoding (a
  tab could otherwise turn `/<tab>/evil.example` into `//evil.example`; it was
  not exploitable), and the template test finds script tags with an HTML
  parser in any case.

### Renamed to Vedette, ready to publish

The project was called NextDNS Sentinel. Its name no longer uses NextDNS's,
and the repository was audited before going public.

- Everything carries the new name: the `vedette` command
  (`docker compose exec vedette vedette findings`), the Python package and
  module, the `VEDETTE_` settings prefix (was `SENTINEL_`), the cookies, the
  Compose project, service, images and the `vedette-data` volume, and the
  default database file `/data/vedette.db`. Existing data moves by copying the
  old volumes into the new ones; the old ones are left in place.
- The README says Vedette is independent of NextDNS Inc., what it has been
  tested on, and where to report a security problem: the new `SECURITY.md`.
- The default time zone is UTC, not Asia/Singapore; `config.example.yaml`
  asks for your own.
- `.env.example` documents `VEDETTE_DASHBOARD__HOST`, the last setting it
  left out.
- Stale passages corrected: the pre-filter and the injection measurement are
  done, the dashboard has eight pages, the confirmation dialog and live open
  counts are described as they now work, and open points that were settled
  are gone.
- The secret scan of the full history and a check for real profile ids,
  device names, domains, keys and the owner's address found nothing to remove.
- `PRODUCT.md` and `DESIGN.md`, the briefs the design tools read, are
  git-ignored and kept only on the owner's machine.
- CI's actions are pinned to release commits. The first run on GitHub could
  not start: `astral-sh/setup-uv` publishes exact releases but no `v10` tag.

### Dashboard: triage polish

From a UX evaluation of the drawing set (`docs/ux/evaluation-dashboard.md`).

- Every rule has a plain name (`name` in `rules.yaml`, optional in an
  override file; the id stands in when it is missing). Findings are titled by
  it on the dashboard, in Discord alerts ("CRITICAL: Threat-feed domain
  allowed, ...") and in the digest; the id stays beside it (a finding's title
  block, the alert's Rule line, the end of each digest entry), where it
  matches `vedette findings --rule`. What the rule checks is on every finding's page,
  not only before the model has explained it.
- Findings open in triage order, highest priority first and then most recently
  seen, as the Overview and J/K already did.
- A decision updates every open count at once: the profile switch, the menu and
  the Overview link, through the decision's response (`HX-Trigger:
  vedette-counts`) and the live stats (`open_by_layer`).
- Mark benign's confirmation opens on Cancel, is titled with the action, sets
  the domain as an outside name and says Reopen undoes it; the dialog's body is
  its accessible description.
- Health shows "Retrying" for a NextDNS API check inside its error window and
  "Catching up" after a start-up, and says in words what NextDNS answered
  ("NextDNS is rate-limiting Vedette since 14:05. Vedette waits and tries
  again."). The alert after the window ends with the HTTP status.
- In a window 1,180px or narrower, a finding's Decision panel follows the
  explanation; at 860px or narrower the Findings filters fold behind one
  control that counts the filters set.
- A new-category-or-blocklist finding shows NextDNS's name for the reason, with
  the id after it.
- Error pages are titled in words ("Finding 0042 not found") inside the title
  block, with the status code as a field. A 429's own message is shown.
- Outside names in a finding's evidence are set like every other outside name;
  Domains names break only at their dots; usual counts of 100 or more drop
  their tenths; a decision no longer changes the findings table's column
  widths.

### Dashboard: the drawing set

A new visual world: every page is a sheet in one
set of drawings, each NextDNS profile draws on its own layer in its own ink
(router teal, pc violet), and every triage decision is entered as a revision
in rose ink. Still dark only; inked decisions are kept.

- One profile switch in the rail: Both, router or pc. It scopes every page,
  chart, table and the live feed, is remembered in a cookie
  (`vedette_scope`, `HttpOnly`, `SameSite=Strict`), and each option shows its
  open findings, so a problem on a profile not shown is never hidden. A link
  to a finding on another profile still opens. New route: `/scope`.
- Charts draw each profile shown as its own layer, stacked, with its blocked
  queries darker within it; a checkbox per layer in the legend hides or shows
  it; the readout splits every count per profile; a dimension line over the
  plot states the span and bar size. `/api/series` gains `layers`.
- Every table heading sorts: numbers, times and priorities the right way
  round, remembered across live refreshes. Works on the findings, the
  decisions table, Domains, Devices, Health, Digests, Evaluation, a finding's
  recent queries and the list under a chart.
- Every control is the dashboard's own: dropdowns are listboxes drawn in its
  ink (keyboard, type-ahead, screen-reader roles; the native select stays in
  the form, so filters work without JavaScript), checkboxes and the "Only
  blocked" switch are drawn, the "Mark benign" confirmation is the dashboard's
  dialog instead of the browser's, and scrollbars, selection and focus rings
  are themed.
- The findings Day filter lists only days that have findings, with counts.
- A finding's explanation leads with the model's reading, then likely cause
  and recommended action side by side, then confidence (a meter), whether the
  model raised the priority, and who decides. Its history is a lettered
  revision list.
- On a finding's page, J and K (or the links) move to the next and previous
  open finding in triage order.
- Every page opens with a title block: what it shows, when it was drawn, and
  its place in the set. The live feed sets time, profile, name, device and
  status in fixed columns.
- The findings table keeps every sortable column down to about 1,000 pixels
  of table width, giving up only Events first.

### Fixes

- The daily digest arrives even when the computer is off at the digest time:
  while no digest exists yet, the latest one is produced late at start-up,
  as later missed ones already were. Before, none was ever made.
- No more "No events from router" followed by "Resolved" after the computer
  has been off for a while: a profile's silence is judged only once its
  collector has caught up after start-up, or after 10 minutes.

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
  `vedette purge` runs it now; `vedette purge --all` wipes all local data.
- The database and everything else Vedette writes are owner-only (umask 077),
  and existing files are tightened at start-up.
- Ollama now runs as a non-root user with a read-only root filesystem; a
  one-shot `ollama-volume-owner` service hands it the model volume.
- New command: `vedette backfill` reads a period of history from the API
  without disturbing the live stream.
- New command: `vedette eval`.
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

- A new visual system, "notices and chart corrections":
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
- New command: `vedette benign <finding>`.
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
- New commands: `vedette notify --test` and `vedette digest`.
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
- `vedette findings` shows the explanation and any raised priority.
- `pytest --live` runs a smoke test against the real model.

### Log export import

- `vedette import FILE --profile NAME` loads a NextDNS dashboard log export.
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
- Findings are stored with de-duplication and listed by `vedette findings`
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

- Repository layout from the spec, packaged as `vedette` with the
  `vedette` command.
- Configuration loading from `config.yaml`, environment variables
  (`VEDETTE_` prefix, `__` nesting) and Docker secrets, with validation and
  one-line error messages. Secrets are refused in the YAML file.
- JSON logging to stdout with redaction of sensitive keys, header mappings and
  known secret values, for both Vedette code and library logs.
- Queue interface with an in-memory implementation.
- `vedette run` starts a pipeline of idle placeholder stages and shuts down
  cleanly on SIGINT or SIGTERM.
- Docker Compose stack: hardened `vedette` container, `ollama` with GPU access
  on an internal-only network, a one-shot `ollama-pull` helper, and a `dev`
  container for lint, type checks and tests.
- CI workflow (ruff, mypy `--strict`, pytest on Python 3.14 and 3.15, pip-audit,
  gitleaks) and a Docker-based gitleaks pre-commit hook.
- `.env.example`, `config.example.yaml`, README quickstart and
  `docs/ARCHITECTURE.md` with the decisions taken so far.
