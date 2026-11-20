# NextDNS Sentinel dashboard

## Users

One owner, on their own Windows 11 PC [PRODUCT.md]. Two uses, both confirmed:

- Short triage visits after the 08:00 digest or an instant alert, deciding each finding in a few minutes.
- The dashboard left open all day as a live monitor, glanced at between other work, often on an ultrawide screen.

The owner is technical (runs Docker, reads JSON logs), but triage must never require reading code or logs. Input is mouse and keyboard; every page also has to work on a phone.

## Product

A local, server-rendered dashboard (FastAPI, Jinja2, htmx, uPlot) served by the pipeline at http://127.0.0.1:8080, reachable from this computer only, behind a login token. Pages: Overview, Live, Findings and a finding's page, Domains, Devices, Digests, Health, Evaluation. Two NextDNS profiles: `router`, which reports no devices, and `pc`, a laptop that reports device names and is often silent for long stretches [PRODUCT.md].

## Constraints

- Strict Content-Security-Policy: no inline scripts or styles, nothing loaded from outside; every asset is served by the dashboard.
- Every name from DNS traffic is escaped and defanged and never becomes a link.
- Every page works without JavaScript.
- The owner's DNS history stays private: no real domain or device names in documents, commits or screenshots that leave the machine.
- The visual world is the night chart recorded in DESIGN.md.

## Ethical stance

- Rules own every alert and its minimum priority; the local model explains and may raise priority, never lower or hide a finding.
- No engagement mechanics: the live feed is capped, and nothing pulls the owner back except real findings.
- Every triage decision is reversible in place and recorded. A decision with a side effect (Mark benign allowlists the domain for the profile) says so and asks first.
- Nothing leaves the machine to render a page.

## Success

The day's findings are triaged entirely from the dashboard in a few minutes, and a glance tells whether anything needs attention and whether the pipeline itself is healthy [PRODUCT.md].

## Open questions

- Is the laptop profile expected to stay silent for weeks? If so, its `stale_after_minutes` or `quiet_hours` in config.yaml stops the Health check, and the menu's status, from reporting a fault.
