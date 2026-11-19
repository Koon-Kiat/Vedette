---
name: NextDNS Sentinel
description: A local DNS watch dashboard drawn as a nautical chart with its notices and corrections, read at night on a live bridge display.
colors:
  ground: "#0a131d"
  rail: "#070e16"
  surface: "#0f1b28"
  surface-2: "#142334"
  surface-3: "#1a2c40"
  line: "#1c2c3d"
  line-strong: "#2a4058"
  ink: "#e7eef6"
  ink-2: "#a3b6c9"
  ink-3: "#7c93ab"
  tint: "#183650"
  tint-2: "#11273b"
  magenta: "#ee6dbf"
  magenta-wash: "#3a1730"
  on-magenta: "#160611"
  primary: "#a9cdea"
  primary-hi: "#d3e6f6"
  on-primary: "#07111b"
  ok: "#5fd39a"
  warn: "#f5c95c"
  problem: "#ff8593"
  critical: "#ff8593"
  critical-bg: "#3a1522"
  critical-line: "#5a2032"
  high: "#ffad7a"
  high-bg: "#3a2216"
  high-line: "#5a3420"
  medium: "#f5c95c"
  medium-bg: "#33290f"
  medium-line: "#4f3f17"
  low: "#8ec3ff"
  low-bg: "#14283f"
  low-line: "#1f3d5e"
  info: "#b3c2d1"
  info-bg: "#1a2533"
  info-line: "#2a394b"
  allowed: "#4f86c0"
  blocked: "#8aa2bb"
  span: "#a9cdea"
typography:
  title:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "28px"
    fontWeight: 650
    lineHeight: 1.15
    letterSpacing: "-0.015em"
    fontFeature: "tnum"
  figure:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "28px"
    fontWeight: 600
    lineHeight: 1.1
    fontFeature: "tnum"
  headline:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "18px"
    fontWeight: 620
    lineHeight: 1.3
    letterSpacing: "-0.005em"
    fontFeature: "tnum"
  subhead:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: 1.55
    fontFeature: "tnum"
  lead:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.55
    fontFeature: "tnum"
  body:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "14px"
    fontWeight: 420
    lineHeight: 1.55
    letterSpacing: "0.005em"
    fontFeature: "tnum"
  label:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "12px"
    fontWeight: 560
    lineHeight: 1.55
    letterSpacing: "0.01em"
    fontFeature: "tnum"
  data-mono:
    fontFamily: "JetBrains Mono, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.55
  outside-name:
    fontFamily: "JetBrains Mono, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.55
rounded:
  key: "3px"
  focus: "4px"
  key-pill: "5px"
  control: "8px"
  panel: "12px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  heading: "14px"
  lg: "16px"
  panel-x: "20px"
  gutter: "24px"
  xl: "32px"
  page-x: "36px"
  section: "40px"
components:
  button:
    backgroundColor: "{colors.surface-2}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "8px 13px"
  button-hover:
    backgroundColor: "{colors.surface-3}"
    textColor: "{colors.ink}"
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "8px 13px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hi}"
    textColor: "{colors.on-primary}"
  button-quiet:
    textColor: "{colors.ink-2}"
    typography: "{typography.label}"
    padding: "0"
  button-decide:
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "10px 15px"
  input:
    backgroundColor: "{colors.surface-2}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "7px 10px"
  rail:
    backgroundColor: "{colors.rail}"
    textColor: "{colors.ink-2}"
    width: "240px"
    padding: "20px 12px 16px"
  rail-link-active:
    backgroundColor: "{colors.surface-2}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "8px 10px"
  count:
    backgroundColor: "{colors.magenta}"
    textColor: "{colors.on-magenta}"
    rounded: "{rounded.pill}"
    padding: "0 7px"
    height: "20px"
  count-zero:
    backgroundColor: "{colors.surface-3}"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.pill}"
  badge-critical:
    backgroundColor: "{colors.critical-bg}"
    textColor: "{colors.critical}"
    rounded: "{rounded.pill}"
    padding: "0 9px"
    width: "68px"
    height: "22px"
  badge-high:
    backgroundColor: "{colors.high-bg}"
    textColor: "{colors.high}"
    rounded: "{rounded.pill}"
    padding: "0 9px"
  badge-medium:
    backgroundColor: "{colors.medium-bg}"
    textColor: "{colors.medium}"
    rounded: "{rounded.pill}"
    padding: "0 9px"
  badge-low:
    backgroundColor: "{colors.low-bg}"
    textColor: "{colors.low}"
    rounded: "{rounded.pill}"
    padding: "0 9px"
  badge-info:
    backgroundColor: "{colors.info-bg}"
    textColor: "{colors.info}"
    rounded: "{rounded.pill}"
    padding: "0 9px"
  chip-blocked:
    backgroundColor: "{colors.surface-3}"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.pill}"
    padding: "0 8px"
    height: "20px"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
    padding: "18px 20px"
  filters:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
    padding: "16px 18px"
  live-line:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink-2}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "8px 14px"
  segmented-active:
    backgroundColor: "{colors.surface-3}"
    textColor: "{colors.ink}"
    rounded: "{rounded.pill}"
    padding: "6px 14px"
  range-button-active:
    backgroundColor: "{colors.surface-3}"
    textColor: "{colors.ink}"
    rounded: "{rounded.pill}"
    padding: "6px 12px"
  chart-dialog:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "22px 24px 18px"
---

# Design System: NextDNS Sentinel

## Overview

**Creative North Star: "Notices and Chart Corrections, at Night"**

The dashboard is a nautical chart kept current by its owner and read on a dimmed bridge display. Every finding is a numbered notice (printed as four digits, `0004`), and every triage decision is written onto the record in magenta, the way a correction is inked onto a chart: the old status struck through, the new status and the time beside it. Nothing is erased; the record only grows.

The world is night only: a deep-water navy ground, never black, with a darker rail and three layered navy surfaces above it. One navy-tinted ramp carries every neutral, line and ink. Depth-tint blue marks the usual (the usual-traffic band in the charts, selection, the span track). Magenta is scarce and means one of two things: something needs attention, or a decision was made. Severity reads as buoy-coloured tinted chips. The density is an operator's instrument: 14px body, tight tables, many figures, all tabular, read in short triage visits or glanced at from across the room while the page is left open as a live monitor.

Mona Sans is the product's own voice, set a touch wider for titles and live figures. JetBrains Mono carries data, and its italic marks every name that came from outside (a domain, a device name), so attacker-controlled text is always visibly someone else's words. The page is visibly live: new queries open their own space and settle, the status dot rings, changed numbers flash once, and the time charts follow the present until the owner zooms away.

**Key Characteristics:**
- Night chart only (`color-scheme: dark`): navy ground, darker rail, surfaces stepping lighter as they rise.
- Magenta reserved for attention (the open count, open-finding markers, a newly arrived finding) and decisions (corrections, history).
- Severity as tinted buoy chips: coloured text on a dark wash of the same hue, with a matching hairline.
- Mona Sans upright for the product; JetBrains Mono for data; JetBrains Mono italic for every outside name.
- Tabular figures everywhere; a five-step ladder (12/14/16/18/28).
- Interactive time charts (uPlot) that follow live, zoom, pan, list a period, and enlarge into a dialog.
- Rounded, softly lifted panels (12px corners, a low diffuse shadow) on the navy ground.

## Colors

A cold night-navy palette with one hot ink (magenta), one pale chart blue for action, and a fixed set of buoy hues for severity.

### Primary
- **Pale Chart Blue** (primary): the one filled button in a row (Acknowledge on an open finding, Pause, log in), the current bar in a time chart and the current minute, selection and picked-period bands, links, and the focus ring. Dark ink (on-primary) on its fill.
- **Pale Chart Blue, Lit** (primary-hi): primary button hover, and the colour a changed live figure flashes from.
- **Span Blue** (span): the seen interval on a finding's 24-hour span bar.

### Secondary
- **Correction Magenta** (magenta): the open-findings count, open-finding markers on the charts, the inked correction on a decided row, the numbered history circles and their actions. Its dark ink (on-magenta) sits on every magenta fill.
- **Magenta Wash** (magenta-wash): the wash under a finding that has just arrived in the Needs a decision table, settling to nothing.

### Tertiary
- **Depth Tint** (tint): the usual-level band behind the bars (at 55%), the usual key, text selection.
- **Shallow Tint** (tint-2): the span-bar track.
- **Allowed Blue** (allowed) and **Blocked Slate** (blocked): the two stacked series in every query chart, allowed below, blocked on top.

### Severity (buoys, as tinted chips)
Each level has a text colour, a dark wash and a hairline in the same hue: **Buoy Red** (critical, critical-bg, critical-line), **Buoy Orange** (high, high-bg, high-line), **Buoy Amber** (medium, medium-bg, medium-line), **Buoy Blue** (low, low-bg, low-line; also the dashed usual line and a span that began on an earlier day), **Buoy Grey** (info, info-bg, info-line).

### Status
- **Pass Green** (ok): a passing pipeline, an open live connection, the "Following live" dot, the ring on the live dot.
- **Signal Amber** (warn): the live dot while connecting.
- **Coral** (problem): failing checks, errors.

### Neutral
One ramp, tinted from the navy.
- **Night Ground** (ground): the page.
- **Rail Dark** (rail): the navigation rail and the bare login/error ground.
- **Surface** (surface), **Surface 2** (surface-2), **Surface 3** (surface-3): panels; then table headers, controls, the current rail link and row hover; then pressed and current segments, the blocked chip, decided-finding markers.
- **Line** (line) and **Strong Line** (line-strong): panel and row rules; control borders, axis ticks, underlines.
- **Ink** (ink), **Second Ink** (ink-2), **Third Ink** (ink-3): text; leads, labels and decided rows; meta, times, ticks and struck statuses.

### Named Rules
**The Two Jobs Rule.** Magenta does exactly two jobs: attention (what needs a decision) and decisions written onto the record. On a chart, an open finding's marker is magenta and a decided finding's marker is a grey pill (surface-3 with a strong-line stroke and second ink). Magenta is never a link, never a primary button, never a data series, never decoration.

**The Buoy Chip Rule.** Severity is only ever told by the five buoy hues, in order critical, high, medium, low, info, and always as a chip: buoy text on its own dark wash with its own hairline. No other colour carries severity.

**The Never Black Rule.** The darkest value is the rail navy; every neutral comes from the navy-tinted ramp. No pure black or pure grey surfaces.

## Typography

**Display Font:** Mona Sans (self-hosted variable woff2, weight 200 to 900, width 75 to 125%; with system-ui, Segoe UI, Roboto)
**Body Font:** Mona Sans
**Label/Mono Font:** JetBrains Mono (self-hosted, normal and italic; with ui-monospace, Cascadia Mono, Consolas)

**Character:** A wide, confident grotesque for everything the product says, set beside a plain coding mono for everything the record holds. The mono's italic is reserved for names that came from outside, so they read as quoted evidence.

### Hierarchy
- **Title** (650, 28px, 1.15, -0.015em, width 112%): page titles and the login heading; one per page.
- **Figure** (600, 28px, 1.1, width 110%): live figures beside the Live chart (peak minute, open findings).
- **Headline** (620, 18px, 1.3, -0.005em, width 106%): section headings above blocks and inside panels; the enlarged chart's title.
- **Sub-heading** (600, 16px): headings inside a panel, the period list's heading, side-panel headings on a finding's page.
- **Lead** (400, 16px, max 72ch): the sentence under a title; a finding's summary (1.6, max 68ch); the current decision.
- **Body** (420, 14px, 1.55, 0.005em): tables, prose, controls in filters, the period readout.
- **Label** (560, 12px, 0.01em): table headers, filter and fact labels, the live pill; buttons at 620; meta at 400 to 450 (stamps, "usual" notes, hints, legends, chart ticks).
- **Data mono** (400, 12px): feed times; at body size, evidence keys and values, code and the digest text.

### Named Rules
**The Outside Voice Rule.** Every name that came from outside is sloped: domains in JetBrains Mono italic (always defanged, never a link), device names in italic. The product's own words are never sloped, and outside names are never upright.

**The Five Steps Rule.** Sizes are 12, 14, 16, 18 and 28, one job per step. Emphasis inside a step is weight (560 to 650), not size.

**The Night Weight Rule.** Light text on the dark ground is set one weight step heavier than it would be on paper (body 420, labels 560, buttons 620) with a touch more letter-spacing (0.005em body, 0.01em labels).

**The Tabular Rule.** Figures are tabular everywhere (`font-variant-numeric: tabular-nums` on the body); numeric columns align right.

## Layout

A two-column shell: a sticky full-height rail (240px) and a main column that fills the screen up to 3200px (a 3440px ultrawide), with 32px top, 72px bottom and 36 to 64px side padding that grows with the window. Pages never stretch one column across a wide screen; they recompose into more columns (see Responsive behaviour). Page heads are a two-column grid: title and lead on the left, a stamp, segmented control or the live pill on the right, 32px above the first block. Blocks stack 40px apart; headings sit 14px above their content. Composite rows use a 24px gutter (32px between board columns): even halves, a finding's main column beside a 360px sticky side column (32px gap).

**Overview order:** the title with the live pill; Needs a decision (the open high and critical findings, refreshed live); Queries over time, full width; Right now (the last eight queries, a fixed-height feed) beside New devices and findings; Today against the usual week. On an ultrawide screen the page becomes a board of two columns (2 to 1, the side at least 440px): Needs a decision and Queries over time on the left; Right now, New devices and findings, and Today against the usual week stacked on the right, both columns starting on one line.

**Live order:** the title with the live pill; Queries over time with the live figures beside its heading and the short (200px) interactive chart; then the Queries feed with its controls (Show N new, Only blocked, Profile, Pause) above a panel that scrolls inside itself, so new rows never push the page. On an ultrawide screen the feed and the chart sit side by side in equal halves, feed on the left; their heads share one height so both panels start on one line, and the chart, which stays in view as the page scrolls, grows with the window (340 to 560px).

Spacing steps observed in reuse: 4, 8, 12, 14, 16, 18/20 (panel insets), 24, 32, 36, 40.

Responsive behaviour:
- **Ultrawide, 2240px and wider:** the Overview and Live boards above; Domains sets its four tables in one row; a finding's page puts the explanation and the cached domain facts beside the evidence, with recent queries across both, next to a 400px side column.
- **Wide, 1800px and wider:** the findings table gives its spare width to the About column (38%), so the domain and why it fired wrap less instead of every column drifting apart.
- **Time charts** ask the server for about one bar per 6px of plot width (60 to 480 bars), so a wider chart shows finer bars, and fetch again when a resize changes that by more than a fifth.
- **Laptop fold, 641 to 1180px:** the findings table hides its wide columns (number, rule, profile and device, last seen, events) and folds them into one meta line under the domain, so the decision buttons stay in view; the rail narrows to 212px and main side padding drops to 28px.
- **1180px and below:** the Overview's side panels and the finding detail collapse to one column; the side column stops sticking.
- **860px and below:** the rail becomes a top bar: brand and log-out on one line, pipeline state below, then the navigation as a horizontally scrolling row that fades out at its right edge instead of drawing a scrollbar. Main padding drops to 22px/16px; feed rows move profile and device onto a second line.
- **640px and below (phone):** each findings row becomes a stacked notice card (14px/16px padding, 12px corners, 10px apart) with the decision and actions on its last line, in thumb reach; time charts drop to 220px (180px short); the enlarged chart fills the screen less 8px.
- **Pointer-less devices:** the chart hint switches to the touch wording.

## Elevation & Depth

Tonal layering first, with a soft lift. Depth is told by stepping the surface lighter as it rises (ground, then surface, surface-2, surface-3) and by 1px navy lines. Panels and table wrappers carry one low, diffuse shadow that only darkens the ground beneath them; it never reads as a hard edge. The enlarged chart dialog is the one raised object, over a near-opaque navy backdrop.

### Shadow Vocabulary
- **Panel lift** (`box-shadow: 0 12px 32px -20px rgb(0 0 0 / 0.65)`): panels and table wrappers on the ground.
- **Login lift** (`box-shadow: 0 24px 60px -24px rgb(0 0 0 / 0.8)`): the single card on the bare rail ground (login, errors).
- **Dialog lift** (`box-shadow: 0 40px 100px -30px rgb(0 0 0 / 0.85)`, backdrop `rgb(3 8 13 / 0.76)`): the enlarged chart.
- **Hairline stroke** (`box-shadow: inset 0 0 0 1px var(--line-strong)`): not depth; the stroke round a decided-finding key.

### Named Rules
**The Rising Surface Rule.** A surface that sits higher is lighter, never more saturated: ground, surface, surface-2, surface-3. Lift comes from tone first; the shadow only softens the ground under it.

## Shapes

Soft, rounded and pill-shaped. Panels, tables, the filters bar, phone notice cards and the chart dialog round at 12px; buttons, inputs, rail links and the period-list boxes at 8px. Every token of state is a full pill: severity chips, the blocked chip, the magenta count, the live pill, the segmented control and the chart's range group. Chart markers are pills drawn half their height round. Legend keys and swatches are 3px squares; the marker keys are 5px pills. Two forms are circles: the live and pipeline dots (8px) and the numbered history circle (22px, 1.5px magenta stroke). Lines are 1px throughout; the heavier strokes are the 2px focus outline (4px radius, 2px offset), the 2px dashed usual line and the 2px magenta strike on a corrected status.

## Components

### Buttons
Compact and quiet; the one filled button in a row is the decision the owner is most likely to make.
- **Shape:** softly rounded (8px).
- **Default:** surface-2 fill, strong-line border, ink text, 12px/620 at 0.01em, 8px 13px; 10px 15px at 14px in a finding's decision bar and the filters bar.
- **Primary:** pale chart blue fill and border, dark ink. Used for Acknowledge on an open finding, Pause on the Live feed (it drops to default while paused, reading Resume), and log in.
- **Quiet:** no border or fill, second ink, underlined at a 3px offset in the strong line. Used for Reopen, Log out, Back to live, Close list.
- **Hover / Focus / Active:** default goes to surface-3 with a third-ink border; primary goes to the lit blue; 2px pale-blue focus outline offset 2px; pressed buttons drop 1px; a pending htmx request dims the form to 0.6 with a progress cursor. Transitions are 120ms.

### Severity Chips
- **Style:** pill, at least 68px wide, 12px/620, buoy text on the buoy wash with a 1px buoy hairline.
- **State:** once a finding is acknowledged or benign, its chip keeps its priority but drops the wash (outline only), and the row's text drops to second ink.

### Cards / Containers
- **Corner Style:** 12px.
- **Background:** surface on the ground; table headers on surface-2.
- **Shadow Strategy:** panel lift (see Elevation & Depth).
- **Border:** 1px line.
- **Internal Padding:** 18px 20px for panels; 16px 18px for the filters bar and chart panels; 22px 24px for the digest text.

### Tables
Wrapped in a 12px bordered panel that scrolls sideways when it must. Headers are 12px/560 second ink on surface-2; cells 12px with line rules between rows; row hover takes surface-2. Compact tables inside panels drop the header fill and outer padding. Key-value evidence tables set both columns in mono.

### Inputs / Fields
- **Style:** surface-2 fill, 1px strong-line border, 8px corners, 7px 10px, at least 9rem wide; labels sit above as 12px/560 second ink; checkboxes take the pale blue accent.
- **Focus:** the global 2px pale-blue outline, offset 1px; hover lifts the border to third ink.

### Navigation
- **Rail:** rail navy, 240px, sticky, a 1px line on its right. Brand in 16px Mona Sans at 110% width, "Sentinel" at 700. Links are 14px/480 second ink at 8px 10px with 8px corners; hover takes surface and ink, the current page surface-2 at 600. Live carries the live dot; Findings carries the magenta open count (a dark surface-3 pill when nothing is open). Pipeline health sits at the foot under a line: a dot and state in pass green or coral, then 12px third-ink "Newest event" meta.
- **Segmented control:** a pill on surface; segments 6px 14px; the current segment fills surface-3 at 600.
- **Mobile:** see Layout.

### Live Signals (signature)
- **Live pill:** a surface pill (8px 14px) with the live dot, the state at 620 and the last minute's queries and blocked count as ink figures in 12px second ink.
- **Live dot:** 8px; pass green when open, signal amber while connecting, third ink when paused or closed. When queries arrive it rings: a 2px green ring scales out and fades (900ms), at most once every 4 seconds and never while paused.
- **Tick:** a changed live figure flashes from the lit blue back to its colour (700ms).
- **Feed row:** time (mono, third ink), the domain (outside name), profile and device (12px second ink), and a blocked chip. A new row first opens its own height (340ms, standard curve) while fading and sliding 4px in from a surface-3 glow (560ms, ease-out); rows past the limit are removed 600ms later, once the new ones have opened. Blocked rows set the domain in second ink. The Right now feed is eight 37px rows at a fixed height, so the panel never grows.
- **Fresh finding:** a finding that arrives in Needs a decision is washed in magenta-wash, holds for a quarter of the time, then settles to nothing over 2400ms.

### Time Chart (signature)
An interactive query chart on uPlot 1.6.32, mounted over the server-drawn SVG chart, which stays in place until the series loads and whenever JavaScript is off.
- **Bars:** each bar is the total in allowed blue, with the blocked share drawn over its foot in blocked slate; the bar still counting is pale chart blue. Behind them the depth-tint band rises to the usual level, and a 2px dashed buoy-blue line marks that level over a 4px surface halo.
- **Markers:** open findings are magenta pills carrying the four-digit notice number in 12px/700 on-magenta, with a hairline drop to the axis; decided findings are grey pills (surface-3, strong-line stroke, second ink). Findings close together share one pill ("0004 +2").
- **Controls:** a pill range group above the plot (6h, 24h, 7d, 30d on Overview; 30m, 1h, 6h, 24h on Live), "Following live" with a soft green dot while the chart shows the present, Back to live once it does not, and Enlarge.
- **Pointer:** drag across to zoom (a pale-blue selection with 1px edges); Ctrl + scroll zooms; Shift + scroll or Shift + drag pans; double-click goes back to live; hovering shows a faint ink band and a two-line readout that never moves the plot; clicking a bar lists that period under the chart; clicking a marker opens its finding, or lists the period when the marker stands for several.
- **Keyboard:** the plot is focusable; left and right move between bars, Shift with the arrows moves through time, Home and End jump to the ends, plus and minus zoom, 0 goes back to live, Enter or Space lists the period. Changes are announced in a polite live region.
- **Period list:** under a line, the period's heading, totals and Close list; the period's findings, when there are any; then Most looked up beside Latest queries as two matching tables in 8px-cornered boxes: the same top, the same sticky header, the same one-line rows and the same height (the header and ten rows, the latest queries scrolling inside), so their rows line up across the gap. Long names end in an ellipsis with the full name as the row's tooltip. One column under 760px of chart width.
- **Enlarge:** the same chart moves into a modal dialog that fills the window less 24px on every side (12px corners) that rises 8px into place (220ms); the page keeps its height while the chart is away, and closing returns it and its focus.

### The Correction (signature)
A decision written onto the record. On a decided row the cell reads, in magenta 620: the old status struck through (third ink, 2px magenta strike), then the new status and the time. In the findings list the struck status sits on its own line above the new one, as on a corrected chart. When a triage action swaps the row in place, the correction is revealed left to right by a clip-path transition (520ms, ease-out); under reduced motion it simply appears. On a finding's page the history lists every correction beside a 22px magenta numbered circle, the action in magenta and its time in meta.

### Span Bar
A 120 by 8 SVG strip under "Last seen": the day as a shallow-tint track with strong-line ticks at 06, 12 and 18, and the seen interval in span blue (buoy blue when it began on an earlier day).

## Do's and Don'ts

### Do:
- **Do** print every finding number as a four-digit notice (`0004`), in the table, the page title and the chart markers alike.
- **Do** write a decision as a correction: struck old status, then new status and time, in correction magenta, and keep every past correction visible in the history.
- **Do** draw open-finding markers in magenta and decided-finding markers as grey pills, on every chart.
- **Do** set every outside name sloped (domains in JetBrains Mono italic, defanged; device names in italic), escaped and never as a link.
- **Do** keep to the 12/14/16/18/28 ladder, the night weights (body 420, labels 560, buttons 620) and tabular figures, with numeric columns right-aligned.
- **Do** let live arrivals open their own space and settle, keep fixed-height feeds fixed, and reserve room for text that changes (readouts, Show N new, Pause/Resume) so nothing under the pointer moves.
- **Do** step surfaces lighter as they rise (ground, surface, surface-2, surface-3) and take every neutral from the navy ramp.
- **Do** give every animation a reduced-motion form: transitions near zero, no ring, feed rows fade in over 200ms, the correction and the dialog simply appear.
- **Do** serve every font, script and stylesheet from `/static/`, with no inline style attributes or inline scripts, so the strict CSP holds.

### Don't:
- **Don't** use magenta for links, primary buttons, decoration or a data series; it means attention or a decision, nothing else.
- **Don't** show severity by any colour outside the five buoys, or as a solid fill instead of a tinted chip.
- **Don't** set the product's own words in italics, or an outside name upright.
- **Don't** use pure black or a neutral grey for any surface; the darkest value is the rail navy.
- **Don't** let a new row, a refreshed table or a changed figure push the page or shift a control.
- **Don't** load fonts, scripts, icons or images from outside `/static/`.
