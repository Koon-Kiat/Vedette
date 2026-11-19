---
name: NextDNS Sentinel
description: A local DNS watch dashboard drawn as a nautical chart with its notices and corrections.
colors:
  deep: "#0f2a44"
  deep-2: "#17395b"
  deep-3: "#26496b"
  on-deep: "#ffffff"
  on-deep-2: "#b3c8db"
  chart-white: "#fbfcfd"
  panel: "#ffffff"
  n1-wash: "#f3f6f9"
  n2-soft-rule: "#e7edf2"
  n3-rule: "#d4dde5"
  n4-control: "#b3c1cd"
  n7-ink-2: "#4b5b6b"
  n10-ink: "#131a21"
  depth-tint: "#cfe4f2"
  depth-tint-2: "#e6f1f9"
  correction-magenta: "#b0177a"
  buoy-red: "#c8102e"
  buoy-orange: "#b84a0b"
  buoy-amber: "#e3a400"
  buoy-amber-ink: "#8a6a00"
  buoy-blue: "#2f6a9e"
  buoy-grey: "#5d6b78"
  ok-green: "#2c7a4b"
  ok-on-deep: "#7fd6a4"
  problem-on-deep: "#ff9aa6"
  blocked-blue: "#7f9cb8"
typography:
  title:
    fontFamily: "\"Segoe UI Variable Text\", \"Segoe UI\", system-ui, -apple-system, Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "24px"
    fontWeight: 650
    lineHeight: 1.25
    letterSpacing: "-0.01em"
    fontFeature: "tnum"
  headline:
    fontFamily: "\"Segoe UI Variable Text\", \"Segoe UI\", system-ui, -apple-system, Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "18px"
    fontWeight: 600
    lineHeight: 1.3
    fontFeature: "tnum"
  lead:
    fontFamily: "\"Segoe UI Variable Text\", \"Segoe UI\", system-ui, -apple-system, Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tnum"
  subhead:
    fontFamily: "\"Segoe UI Variable Text\", \"Segoe UI\", system-ui, -apple-system, Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: 1.5
    fontFeature: "tnum"
  body:
    fontFamily: "\"Segoe UI Variable Text\", \"Segoe UI\", system-ui, -apple-system, Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tnum"
  label:
    fontFamily: "\"Segoe UI Variable Text\", \"Segoe UI\", system-ui, -apple-system, Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "12px"
    fontWeight: 600
    lineHeight: 1.5
    fontFeature: "tnum"
  outside-domain:
    fontFamily: "\"Cascadia Mono\", \"Cascadia Code\", Consolas, ui-monospace, Menlo, monospace"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
  record-mono:
    fontFamily: "\"Cascadia Mono\", \"Cascadia Code\", Consolas, ui-monospace, Menlo, monospace"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
rounded:
  hairline: "2px"
  badge: "3px"
  control: "4px"
  segmented: "5px"
  panel: "6px"
  count: "10px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  panel-x: "20px"
  rail-x: "22px"
  gutter: "28px"
  page-x: "32px"
  section: "36px"
components:
  button:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.n10-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
  button-primary:
    backgroundColor: "{colors.deep}"
    textColor: "{colors.on-deep}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
  button-primary-hover:
    backgroundColor: "{colors.deep-2}"
    textColor: "{colors.on-deep}"
  button-quiet:
    textColor: "{colors.n7-ink-2}"
    typography: "{typography.label}"
    padding: "7px 12px"
  button-decide:
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "9px 14px"
  input:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.n10-ink}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "6px 8px"
  rail:
    backgroundColor: "{colors.deep}"
    textColor: "{colors.on-deep-2}"
    width: "232px"
  rail-link-active:
    backgroundColor: "{colors.deep-2}"
    textColor: "{colors.on-deep}"
    padding: "8px 22px"
  count:
    backgroundColor: "{colors.correction-magenta}"
    textColor: "{colors.on-deep}"
    rounded: "{rounded.count}"
    padding: "0 7px"
    height: "20px"
  badge-critical:
    backgroundColor: "{colors.buoy-red}"
    textColor: "{colors.on-deep}"
    rounded: "{rounded.badge}"
    padding: "0 8px"
    width: "64px"
  badge-high:
    backgroundColor: "{colors.buoy-orange}"
    textColor: "{colors.on-deep}"
    rounded: "{rounded.badge}"
    padding: "0 8px"
  badge-medium:
    backgroundColor: "{colors.buoy-amber}"
    textColor: "{colors.n10-ink}"
    rounded: "{rounded.badge}"
    padding: "0 8px"
  badge-low:
    backgroundColor: "{colors.buoy-blue}"
    textColor: "{colors.on-deep}"
    rounded: "{rounded.badge}"
    padding: "0 8px"
  badge-info:
    backgroundColor: "{colors.buoy-grey}"
    textColor: "{colors.on-deep}"
    rounded: "{rounded.badge}"
    padding: "0 8px"
  panel:
    backgroundColor: "{colors.panel}"
    rounded: "{rounded.panel}"
    padding: "18px 20px"
  filters:
    backgroundColor: "{colors.n1-wash}"
    rounded: "{rounded.panel}"
    padding: "14px 16px"
  segmented-active:
    backgroundColor: "{colors.deep}"
    textColor: "{colors.on-deep}"
    rounded: "{rounded.segmented}"
    padding: "6px 14px"
---

# Design System: NextDNS Sentinel

## Overview

**Creative North Star: "Notices and Chart Corrections"**

The dashboard is a nautical chart kept current by its owner. Every finding is a numbered notice (printed as four digits, `0004`), and every triage decision is written onto the record in magenta, the way a correction is inked onto a chart: the old status struck through, the new status and the time beside it. Nothing is erased; the record only grows.

The world is a deep-water navy rail beside a chart-white ground. One navy-tinted neutral ramp carries all text, rules and washes. Depth-tint blues mark the usual (the usual-traffic band in the chart, the span track, selection). Magenta is scarce and means one of two things: something needs attention, or a decision was made. Severity borrows buoy colours. The density is that of an operator's instrument: 14px body, tight tables, many figures, all tabular, read in short triage visits or glanced at from across the room.

Upright system sans is the product's own voice. Anything that came from outside the product (a domain, a device name) is set sloped, so attacker-controlled text is always visibly someone else's words. Drawings are SVG geometry rendered by the server; there is no charting script, no icon font, no image.

**Key Characteristics:**
- Navy rail (232px) holding navigation, the magenta open-findings count and pipeline health at its foot.
- Chart-white ground with white panels, 1px navy-grey rules, 6px corners, no resting shadows.
- Magenta reserved for attention (counts, chart markers) and decisions (corrections, history).
- Buoy severity: red, orange, amber with dark ink, blue, grey.
- Upright sans for the product; sloped mono for domains; sloped sans for devices.
- Tabular figures on every page; a five-step type ladder (12/14/16/18/24).
- A "night chart" dark mode: the same world under a dimmed bridge, driven by `prefers-color-scheme`.

## Colors

A cold navy-and-paper chart palette with one hot ink (magenta) and a fixed set of buoy colours for severity.

### Primary
- **Deep-Water Navy** (deep): the rail, the bare login/error ground, primary buttons, the selected segment, the span bar's seen interval and the allowed bars in the chart. In the night chart the primary action role flips to a pale chart blue so it stays visible against the dark ground.
- **Navy Shoal** (deep-2): rail hover and current-page fill; primary button hover.
- **Navy Sounding Line** (deep-3): the hairline that separates pipeline status from the rail navigation.
- **Rail Ink** (on-deep) and **Rail Ink, Second** (on-deep-2): current and resting rail text.

### Secondary
- **Correction Magenta** (correction-magenta): the open-findings count, the finding markers in the chart, the inked correction on a decided row, the numbered history circles, the caret. Nothing else.

### Tertiary
- **Depth Tint** (depth-tint): the usual-level band behind the hourly bars, the usual key, text selection.
- **Shallow Tint** (depth-tint-2): the span-bar track.
- **Blocked Blue** (blocked-blue): blocked queries stacked on top of the navy allowed bars.

### Severity (buoys)
- **Buoy Red** (buoy-red): critical.
- **Buoy Orange** (buoy-orange): high.
- **Buoy Amber** (buoy-amber): medium, always with dark ink (n10-ink) on the filled badge; as outline or text it darkens to **Amber Ink** (buoy-amber-ink) for contrast.
- **Buoy Blue** (buoy-blue): low; also the dashed usual line and the span bar for an interval that began on an earlier day.
- **Buoy Grey** (buoy-grey): info.
- **Pass Green** (ok-green) for a passing health check; on the navy rail, health uses **Rail Green** (ok-on-deep) and **Rail Coral** (problem-on-deep).

### Neutral
One ramp, tinted from the navy. Light values below; the night chart inverts the ramp (see sidecar).
- **Chart White** (chart-white): page ground.
- **Panel White** (panel): panels, tables, controls.
- **Wash** (n1-wash): table headers, the filters bar, row hover.
- **Soft Rule** (n2-soft-rule): rules between table rows and figure lines; chart gridlines.
- **Rule** (n3-rule): panel and table borders, header underlines.
- **Control Line** (n4-control): button and input borders, chart axis.
- **Second Ink** (n7-ink-2): meta, labels, struck old statuses, decided rows.
- **Ink** (n10-ink): text.

### Named Rules
**The Two Jobs Rule.** Magenta does exactly two jobs: attention (what needs a decision) and decisions written on the record. It is never decoration, never a link colour, never a chart series.

**The Buoy Rule.** Severity is only ever told by the five buoy colours, in order critical, high, medium, low, info. The filled buoy fills are fixed in both modes; outline and text forms use the mode's severity ink.

**The One Ramp Rule.** Every neutral comes from the navy-tinted ramp (n0 to n10). No pure greys.

## Typography

**Body Font:** Segoe UI Variable Text (with Segoe UI, system-ui, -apple-system, Roboto, Helvetica Neue, Arial)
**Label/Mono Font:** Cascadia Mono (with Cascadia Code, Consolas, ui-monospace, Menlo)

**Character:** A plain, upright operator's sans for everything the product says, set against a sloped mono that makes outside names look like quoted evidence. The stack is the system's because the strict CSP forbids external fonts and no self-hosted face has been approved.

### Hierarchy
- **Title** (650, 24px, 1.25, -0.01em): page titles and the login heading; one per page.
- **Headline** (600, 18px, 1.3): section headings above blocks and inside panels.
- **Sub-heading** (600, 16px): headings inside a panel; side-panel headings on a finding's page.
- **Lead** (400, 16px, max 75ch): the sentence under a title; a finding's summary (line-height 1.55, max 68ch); the current decision.
- **Body** (400, 14px, 1.5): tables, prose, controls in filters, the digest text.
- **Label** (600, 12px): table headers, filter labels, fact terms, button text in rows, counts; at 400 it carries meta (stamps, "usual" notes, evidence lines, legends, chart ticks).

### Named Rules
**The Outside Voice Rule.** Every name that came from outside is sloped: domains in italic mono (always defanged, never a link), device names in italic sans. The product's own words are never sloped, and outside names are never upright.

**The Five Steps Rule.** Sizes are 12, 14, 16, 18, 24 and nothing else, one job per step. Emphasis inside a step is weight (600 to 650), not size.

**The Tabular Rule.** Figures are tabular everywhere (`font-variant-numeric: tabular-nums` on the body); numeric columns align right.

## Layout

A two-column shell: a sticky full-height navy rail (232px) and a main column capped at 1260px with 28px top, 32px side and 64px bottom padding. Page heads are a two-column grid: title and lead on the left, a stamp or segmented control on the right. Sections stack at 36px; within a section, headings sit 12px above their content.

Composite rows use a 28px gutter: the overview's chart beside its comparison panel (1.65fr to 1fr, the side never under 320px), a finding's main column beside a 340px sticky side column (32px gap), two- and three-up block grids.

Spacing steps observed in reuse: 4, 8, 12, 16, 20/22 (panel and rail insets), 28, 32, 36.

Responsive behaviour:
- **Under 1100px:** split and detail layouts collapse to one column; the side column stops sticking.
- **Under 860px:** the rail becomes a top bar: brand and log-out on one line, pipeline state below, then the navigation as a horizontally scrolling row that fades out at its right edge instead of drawing a scrollbar. Main padding drops to 20px/16px.
- **Under 640px:** each findings row becomes a stacked notice card (14px/16px padding, 6px corners, 10px apart) with the decision and actions on its last line, in thumb reach.

## Elevation & Depth

Flat. Depth is told by tone and rule: chart-white ground, white panels with a 1px rule, a wash for headers and the filters bar, navy for the rail. There are no resting shadows on the app surfaces.

### Shadow Vocabulary
- **Login lift** (`box-shadow: 0 18px 40px rgb(3 10 18 / 0.35)`): the single card on the bare navy ground (login, errors), so it reads as a sheet laid on the water.
- **Outline stroke** (`box-shadow: inset 0 0 0 1px currentColor`): not depth; the outline drawn round a decided finding's priority badge.

### Named Rules
**The Flat Chart Rule.** Surfaces in the app shell never cast shadows. A boundary is a 1px rule or a change of wash.

## Shapes

Small, quiet corners and hairlines. Panels, tables, the filters bar and mobile notice cards round at 6px; buttons and inputs at 4px; the segmented control at 5px; severity badges at 3px; swatches, keys and the focus ring at 2px. Two forms are fully round: the magenta count pill (10px) and the numbered history circle (22px, 1.5px magenta stroke). Chart markers are magenta pills (rx 7.5). Borders are 1px throughout, in the rule or control-line tones; the only heavier strokes are the 2px focus outline and the 2px magenta strike on a corrected status.

## Components

### Buttons
Compact, bordered and plain; the one filled button in a row is the decision the owner is most likely to make.
- **Shape:** gently squared (4px).
- **Default:** panel white, control-line border, ink text, 12px/600, 7px 12px; 9px 14px at 14px in a finding's decision bar and the filters bar.
- **Primary:** deep-water navy fill and border, white text. Used for "Acknowledge" on an open finding, and for login.
- **Quiet:** no border or fill, second ink, underlined at a 3px offset. Used for "Reopen" and "Log out".
- **Hover / Focus / Active:** border darkens to second ink (primary goes to navy shoal); 2px focus outline offset 2px; pressed buttons drop 1px; a pending htmx request dims the form to 0.6 with a progress cursor. Transitions are 120ms on colour only.

### Severity Badges
- **Style:** filled buoy colour, white text (dark ink on amber), 12px/650, 20px tall, at least 64px wide, 3px corners.
- **State:** once a finding is acknowledged or benign, its badge keeps its priority but is drawn in outline in the severity ink, and the row's text drops to second ink.

### Cards / Containers
- **Corner Style:** 6px.
- **Background:** panel white on chart white; filters bar on the wash.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Border:** 1px rule.
- **Internal Padding:** 18px 20px for panels; 14px 16px for the filters bar and chart panel; 20px 22px for the digest text.

### Tables
Wrapped in a 6px bordered panel that scrolls sideways when it must. Headers are 12px/600 second ink on the wash; cells 11px 12px with soft rules between rows; row hover takes the wash. Compact tables inside panels drop the wash and outer padding. Key-value evidence tables set both columns in upright mono.

### Inputs / Fields
- **Style:** panel white, 1px control-line border, 4px corners, 6px 8px, at least 9rem wide; labels sit above as 12px/600 second ink.
- **Focus:** the global 2px navy outline (pale blue at night), offset 1px.

### Navigation
- **Rail:** navy, 232px, sticky. Brand in 16px/650 white. Links are 14px rail-ink-second at 8px 22px; hover and the current page fill with navy shoal and turn white, the current page at 600. Findings carries the magenta count pill. Pipeline health sits at the foot under a sounding-line rule: a dot and state in rail green or rail coral, then 12px "Newest event" meta. Focus rings turn white inside the rail.
- **Segmented control:** bordered (5px), segments 6px 14px; the current segment fills navy.
- **Mobile:** see Layout.

### Hourly Chart (signature)
Server-computed SVG, 720 by 220 viewBox. Stacked bars per hour: navy allowed below, blocked blue on top, 2px apart. Behind them, the depth-tint band rises to the usual hourly level (7-day average), and a 2px dashed buoy-blue line marks that level over a 4px panel-coloured halo. Finding markers are magenta pills carrying the four-digit notice number in 12px/700 white, set above the bar they belong to and stacked when they collide. Ticks every three hours in 12px second ink. A legend of small keys sits beneath.

### Span Bar
A 120 by 8 SVG strip under "Last seen": the day as a shallow-tint track with hairline ticks at 06, 12 and 18, and the seen interval in navy (buoy blue when it began on an earlier day).

### The Correction (signature)
A decision written onto the record. On a decided row the cell reads, in magenta 600: the old status struck through (second ink, 2px magenta strike), then the new status and the time. In the findings list the struck status sits on its own line above the new one, as on a corrected chart. When a triage action swaps the row in place, the correction is revealed left to right by a clip-path transition (520ms, `cubic-bezier(0.16, 1, 0.3, 1)`); under reduced motion it simply appears. On a finding's page the history lists every correction with a 22px magenta numbered circle, the action in magenta and its time in meta.

## Do's and Don'ts

### Do:
- **Do** print every finding number as a four-digit notice (`0004`), in the table, the page title and the chart markers alike.
- **Do** write a decision as a correction: struck old status, then new status and time, in correction magenta, and keep every past correction visible in the history.
- **Do** set every outside name sloped (domains in italic mono, defanged; device names in italic sans), escaped and never as a link.
- **Do** keep to the 12/14/16/18/24 ladder and tabular figures, with numeric columns right-aligned.
- **Do** draw every chart, bar, marker and key as server-rendered SVG geometry or CSS shapes styled from `/static/style.css`, so the strict CSP needs no inline style or script.
- **Do** keep a decided finding's priority visible as an outline badge rather than removing it.
- **Do** take every neutral from the navy-tinted ramp, and give the night chart its own values for each token rather than inverting with filters.

### Don't:
- **Don't** use magenta for links, buttons, decoration or a data series; it means attention or a decision, nothing else.
- **Don't** show severity by any colour outside the five buoys, and don't put white text on the amber buoy.
- **Don't** set the product's own words in italics, or an outside name upright.
- **Don't** load fonts, scripts, icons or images from outside `/static/`, or use inline `style` attributes or inline scripts.
- **Don't** cast shadows on app surfaces; the login lift on the bare navy ground is the only one.
- **Don't** animate anything but the correction reveal and 120ms colour changes, and never when reduced motion is requested.
