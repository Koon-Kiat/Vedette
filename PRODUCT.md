# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

One person: the owner of the NextDNS account, on their own Windows 11 PC. They
use the dashboard two ways, both confirmed:

- **Short visits** after the 08:00 daily digest or an instant alert, to triage
  the day's findings in a few minutes.
- **Left open all day** on a screen as a live monitor, glanced at between other
  work.

There are no other users and no roles. The owner is technical (runs Docker,
reads JSON logs) but the dashboard should not require reading code or logs.

## Product Purpose

NextDNS Sentinel ingests the owner's NextDNS query logs, flags suspicious DNS
activity with deterministic rules, and uses a local language model only to
explain and prioritise what the rules found. The dashboard is where the owner
sees that activity and decides what each finding is.

Success for the dashboard: a day's findings can be triaged entirely from it
(acknowledge, mark benign, reopen), and a glance tells the owner whether
anything needs attention and whether the pipeline itself is healthy.

## Positioning

Rules own every alert and its minimum severity; the model can explain and
raise priority, never lower or hide a finding. Everything runs on the owner's
machine: no paid APIs, no cloud model, DNS history stays local. Domain names
are treated as attacker-controlled text everywhere, including on this page.

## Operating Context

- Runs as Docker Compose on Windows 11 with WSL2 and an NVIDIA GPU (Ollama,
  `qwen3:8b`). The dashboard is served by the pipeline itself at
  http://127.0.0.1:8080, reachable from this computer only, behind a login
  token.
- Two NextDNS profiles today: `router`, which reports no device information
  (device attribution unavailable), and `pc`, a laptop profile that reports
  device ids and names and is often silent for hours.
- The daily digest arrives at 08:00 Asia/Singapore; instant alerts go out for
  fresh high and critical findings once a notification channel is chosen (none
  is chosen yet, so messages are kept, not sent).
- Scale: the router profile produces tens of thousands of queries a day;
  findings so far are a handful a week.

## Capabilities and Constraints

- Pages: Overview, Findings (filters: profile, device, rule, minimum priority,
  status, day; triage actions), a finding's detail (explanation, evidence,
  cached domain facts, recent queries, history), Domains (24 hours or 7 days),
  Devices, Digests, Health, Evaluation (results of `sentinel eval`).
- Severity levels, highest first: critical, high, medium, low, info. Finding
  statuses: open, acknowledged, benign.
- Terminology: finding, rule, priority (effective) and floor (the rule's),
  profile, device, root (registered domain), defanged (`example[.]com`),
  acknowledge, mark benign, reopen, digest, health check.
- Server-rendered Jinja2 with htmx 2 for filtering and row actions; every page
  also works without JavaScript.
- Strict Content-Security-Policy: `default-src 'self'`, no inline scripts or
  styles, no CDNs, no external fonts or images. Anything the page needs must be
  served from the app's own `/static/`.
- Every domain is shown defanged and never as a link; every link is to the
  dashboard's own pages. Device names, reasons and model text are untrusted
  and always escaped.
- Data shown can be sparse (a new install, a silent profile) or hostile
  (payload-shaped domain and device names); both must render cleanly.

## Brand Commitments

The product name is "NextDNS Sentinel". There is no logo, mascot or brand
palette. NextDNS is a third-party service; its marks are not used.

## Evidence on Hand

- Synthetic fixture data for every page: `tests/web_fixture.py`, plus hostile
  payloads in `tests/integration/test_web_xss.py`.
- `docs/example-digest.txt`, a digest rendered from test data.
- The owner's real data lives only in the local database. It is private: never
  put real domain names or device names in screenshots, docs or commits.

## Product Principles

1. Triage first: what needs a decision today is the first thing seen.
2. Rules decide, the model explains; the interface never implies otherwise.
3. Attacker text is data: shown plainly, escaped, defanged, never actionable.
4. Honest about gaps: say "not analysed yet", "attribution unavailable" or
   "no data" rather than hiding or guessing.
5. Private by default: nothing leaves the machine to render this page.
