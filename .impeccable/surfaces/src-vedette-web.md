---
version: 1
slug: "src-vedette-web"
primary_target: "src/vedette/web"
related_targets: []
---

# Dashboard (src/vedette/web)

Scope: every page of the local dashboard (Overview, Live, Findings and a
finding's detail, Domains, Devices, Digests, Health, Evaluation, login, errors).
Visitor mode: Operate.

Audience and job: the owner alone, in short triage visits after the digest or
an alert, and with the page left open all day as a live monitor. Triaging the
day's findings matters most. The owner asked for a more professional and
futuristic dark dashboard, every control custom-made, sortable table headings,
and an easy way to see router, pc or both on every page and chart.

Confirmed answers (2026-11-20): one global profile switch, remembered, with
each option's open-findings count; with both shown, every query chart draws
each profile as its own series; avoid a neon gamer look, a generic admin
template, too dense and too sparse; keep dark only and inked triage decisions.

Constraints: strict CSP (no inline styles or scripts, nothing external; fonts
self-hosted), server-rendered with htmx plus same-origin scripts, every
outside name escaped and defanged, no links built from log data, every page
usable without JavaScript.

Memorable moment: switching the layer re-inks every chart, table and feed; a
decision entered as a revision, the old status struck in place.

Unresolved: none.

## Direction contract

THESIS: Every page is a sheet in one drawing set. Each profile draws on its own layer in its own ink, and every triage decision is entered as a revision: the old status struck, the new one written with its time, never erased. It refuses KPI tiles over a grey table, and the neon HUD.

OWN-WORLD: Graphite drafting ground, cool and near-neutral (not navy), sheets and panels one step lighter, hairline linework. Layer inks carry real jobs: router teal, pc violet, revision rose for decisions and attention. Severity as tinted chips (critical red, high orange, medium amber, low blue, info grey). Mona Sans, expanded for titles and title-block figures; JetBrains Mono for data, its italic marking every outside name; tabular figures. A title block heads each sheet (what it shows, when drawn, its place in the set), dimension lines mark chart spans, revision deltas mark decisions. Every control is drawn in this ink: selects, checkboxes, switches, segmented controls, dialogs.

STORY: The owner sees which layers are shown and what needs a decision, reads why each finding fired, decides in place, and can separate router from pc anywhere with one switch.

FIRST VIEWPORT: Rail: brand and sheet name; the layer switch (Both, router, pc, each with its open count); navigation; pipeline status at the foot. Main: the title block (title, the lead, what is shown, the last minute, when drawn, revisions today); "Needs a decision" with sortable headings; queries over time drawn per profile layer under a dimension line, revision markers keyed to finding numbers, legend toggles per layer; "Right now" with each row inked by its layer. Ultrawide: two columns.

FORM: assigned direction, position 5 of 7; seed:fbe2605e9bc5e46b. Signature interaction: the layer switch re-inks every sheet in place; a decision is entered as a revision (delta, letter, old status struck, new status, time). Raises: dense tabular columns (from Datamatics); next open finding one key away (from Vertical Feed); span bars on one exact 24-hour axis (from Labanotation).

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
