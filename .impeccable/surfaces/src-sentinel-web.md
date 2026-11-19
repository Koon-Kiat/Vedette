---
version: 1
slug: "src-sentinel-web"
primary_target: "src/sentinel/web"
related_targets: []
---

# Dashboard (src/sentinel/web)

Scope: every page of the local dashboard (Overview, Findings and a finding's
detail, Domains, Devices, Digests, Health, Evaluation, login, errors).
Visitor mode: Operate.

Audience and job: the owner alone, in short triage visits after the digest or
an alert, and with the page left open all day as a monitor. The job that
matters most is triaging the day's findings.

Constraints: strict CSP (no inline styles or scripts, nothing external),
server-rendered with htmx, works without JavaScript, every outside name
escaped and defanged, no links built from log data.

Memorable moment: a triage decision inked onto the row in magenta.

Unresolved: none.

## Direction contract

THESIS: Each finding is a numbered notice and each triage decision is written
onto the record in magenta, like a correction on a nautical chart. It refuses
the category default of KPI tiles over a grey findings table.

OWN-WORLD: Deep-water navy rail; chart-white ground; neutrals from one
navy-tinted ramp; depth-tint blue for the usual-traffic band and selected
surfaces; magenta only for attention and corrections; severity in buoy red,
orange, amber, blue and grey. Upright system sans for the product's own words,
sloped type for every name from outside (domains in sloped mono, device names
in sloped sans), tabular figures everywhere, a five-step type ladder.

STORY: The owner sees what needs a decision and whether the pipeline is
healthy, reads why each finding fired, decides in place, and sees every
decision stay on the record.

FIRST VIEWPORT: Navy rail on the left: navigation, the open-findings count in
magenta, pipeline status at its foot. Main: title with the date and "N
findings need a decision"; the needs-a-decision table first (number,
priority, rule, about with an evidence line, profile and device, a span bar
for when it was seen, events, actions). Below: queries per hour over the
depth-tint band of the usual hourly level, with magenta markers keyed to
finding numbers, beside a today-against-usual table and new devices.

FORM: grounded list, position 7 of 7; seed:2299fde56ec293aa. Signature
interaction: a triage action swaps the row in place and the magenta
correction (struck old status, new status, time) is inked in left to right.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
