---
version: 1
slug: "src-sentinel-web"
primary_target: "src/sentinel/web"
related_targets: []
---

# Dashboard (src/sentinel/web)

Scope: every page of the local dashboard (Overview, Live, Findings and a
finding's detail, Domains, Devices, Digests, Health, Evaluation, login, errors).
Visitor mode: Operate.

Audience and job: the owner alone, in short triage visits after the digest or
an alert, and with the page left open all day as a live monitor. The job that
matters most is triaging the day's findings; the owner asked for a dark,
modern dashboard that is visibly live.

Constraints: strict CSP (no inline styles or scripts, nothing external; fonts
self-hosted), server-rendered with htmx plus one same-origin script for the
live feed (server-sent events, written with textContent only), every outside
name escaped and defanged, no links built from log data.

Memorable moment: a triage decision inked onto the row in magenta; a new
finding arriving live under a magenta wash.

Unresolved: none.

## Direction contract

THESIS: Each finding is a numbered notice and each triage decision is written
onto the record in magenta, like a correction on a nautical chart, read at
night on a live bridge display. It refuses the category default of KPI tiles
over a grey findings table, and the neon-on-black monitoring cliche.

OWN-WORLD: Night chart only: a navy ground, never black, with a darker rail
and layered navy surfaces; neutrals from one navy-tinted ramp; depth-tint blue
for the usual-traffic band; magenta only for attention and corrections;
severity as buoy-coloured tinted chips. Mona Sans for the product's voice
(wider for titles and live figures), JetBrains Mono for data with its italic
marking every name from outside, tabular figures everywhere, a five-step type
ladder (12, 14, 16, 18, 28).

STORY: The owner sees what needs a decision, that the pipeline is alive and
healthy, reads why each finding fired, decides in place, and watches queries
arrive as they happen.

FIRST VIEWPORT: Navy rail on the left: navigation with Live (a status dot)
and the open-findings count in magenta, pipeline status and newest event at
its foot. Main: title, "N findings need a decision", and a live pill with
queries and blocked in the last minute; the needs-a-decision table first,
refreshed live; below, across the full width, queries over time over the
usual band with magenta markers keyed to finding numbers: a live, interactive
chart (ranges, drag or Ctrl + scroll to zoom, Shift to move through time,
hover readout, click a bar to list that period, Enlarge into a dialog); then
"Right now", the last queries streaming in, beside new devices and findings.
On the owner's ultrawide screen the Overview is a two-column board instead:
decisions and the chart on the left, the live and daily panels on the right;
the Live page sets the feed beside the chart.

FORM: grounded list, position 7 of 7; seed:2299fde56ec293aa. Signature
interaction: a triage action swaps the row in place and the magenta
correction (struck old status, new status, time) is inked in left to right;
live arrivals open their own space and settle, never jumping the page.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
