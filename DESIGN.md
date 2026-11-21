---
name: Vedette
description: A local DNS watch dashboard drawn as one set of technical drawings, each profile on its own inked layer and every triage decision entered as a revision.
colors:
  rail: "#0a0b0c"
  ground: "#0d0e10"
  sheet: "#0f1012"
  panel: "#141518"
  panel-2: "#1a1c1f"
  panel-3: "#212327"
  line: "#222428"
  line-strong: "#2e3136"
  line-ink: "#454950"
  frame: "#5c616a"
  ink: "#e3e5e8"
  ink-2: "#adb1b8"
  ink-3: "#858a92"
  layer-0: "#adb1b8"
  layer-0-dim: "#5b5f66"
  layer-1: "#45c6cf"
  layer-1-dim: "#1f6d74"
  layer-2: "#a78bfa"
  layer-2-dim: "#5a4699"
  layer-3: "#a9d46f"
  layer-3-dim: "#4a6630"
  layer-4: "#c8b9a6"
  layer-4-dim: "#5f574c"
  rev: "#ff80ae"
  rev-wash: "#33121f"
  on-rev: "#1e0710"
  usual: "#cfd2d7"
  band: "#191a1d"
  now-wash: "rgb(227 229 232 / 0.2)"
  critical: "#ff7171"
  critical-bg: "#2b1316"
  critical-line: "#5b2329"
  high: "#ffa264"
  high-bg: "#2a1b11"
  high-line: "#5a3620"
  medium: "#f0c95a"
  medium-bg: "#262011"
  medium-line: "#4e4119"
  low: "#8fb6ff"
  low-bg: "#121d31"
  low-line: "#233a5d"
  info: "#b6c2ce"
  info-bg: "#1b1c20"
  info-line: "#33363c"
  ok: "#6fd69a"
  warn: "#f0c95a"
  problem: "#ff7171"
typography:
  display:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "30px"
    fontWeight: 640
    lineHeight: 1.1
    letterSpacing: "-0.022em"
    fontVariation: "'wdth' 122"
  headline:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "17px"
    fontWeight: 620
    letterSpacing: "-0.01em"
    fontVariation: "'wdth' 110"
  title:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "15px"
    fontWeight: 620
  summary:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: 1.55
  body:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "'tnum'"
  label:
    fontFamily: "Mona Sans, system-ui, Segoe UI, Roboto, sans-serif"
    fontSize: "12px"
    fontWeight: 400
  data:
    fontFamily: "JetBrains Mono, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "13px"
    fontWeight: 400
    fontFeature: "'tnum'"
  outside-name:
    fontFamily: "JetBrains Mono, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "0.93em"
    fontWeight: 400
  chip:
    fontFamily: "JetBrains Mono, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "11px"
    fontWeight: 620
    lineHeight: 1.4
rounded:
  frame: "2px"
  control: "3px"
  chip: "4px"
spacing:
  field-gap: "6px"
  heading-gap: "12px"
  panel-y: "16px"
  panel-x: "18px"
  column-gutter: "32px"
  block-gap: "34px"
  main-x: "40px"
components:
  button:
    backgroundColor: "{colors.panel-2}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
  button-hover:
    backgroundColor: "{colors.panel-3}"
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.sheet}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
  button-quiet:
    backgroundColor: "transparent"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
  segmented:
    backgroundColor: "{colors.panel}"
    rounded: "{rounded.control}"
    padding: "2px"
  segmented-current:
    backgroundColor: "{colors.panel-3}"
    textColor: "{colors.ink}"
    rounded: "{rounded.chip}"
    padding: "5px 12px"
  layer-option:
    textColor: "{colors.ink-2}"
    rounded: "{rounded.control}"
    padding: "8px 10px"
  layer-option-current:
    backgroundColor: "{colors.panel-3}"
    textColor: "{colors.ink}"
  nav-count:
    backgroundColor: "{colors.rev}"
    textColor: "{colors.on-rev}"
    rounded: "{rounded.chip}"
    typography: "{typography.data}"
    padding: "0 7px"
  titleblock:
    backgroundColor: "{colors.panel}"
    rounded: "{rounded.frame}"
    padding: "18px 22px"
  panel:
    backgroundColor: "{colors.panel}"
    rounded: "{rounded.frame}"
    padding: "16px 18px"
  badge-critical:
    backgroundColor: "{colors.critical-bg}"
    textColor: "{colors.critical}"
    rounded: "{rounded.chip}"
    typography: "{typography.chip}"
    padding: "2px 7px"
  badge-high:
    backgroundColor: "{colors.high-bg}"
    textColor: "{colors.high}"
    rounded: "{rounded.chip}"
    typography: "{typography.chip}"
    padding: "2px 7px"
  badge-medium:
    backgroundColor: "{colors.medium-bg}"
    textColor: "{colors.medium}"
    rounded: "{rounded.chip}"
    typography: "{typography.chip}"
    padding: "2px 7px"
  badge-low:
    backgroundColor: "{colors.low-bg}"
    textColor: "{colors.low}"
    rounded: "{rounded.chip}"
    typography: "{typography.chip}"
    padding: "2px 7px"
  badge-info:
    backgroundColor: "{colors.info-bg}"
    textColor: "{colors.info}"
    rounded: "{rounded.chip}"
    typography: "{typography.chip}"
    padding: "2px 7px"
  select-button:
    backgroundColor: "{colors.panel-2}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "7px 10px"
  select-list:
    backgroundColor: "{colors.panel-2}"
    rounded: "{rounded.frame}"
    padding: "4px"
  input-text:
    backgroundColor: "{colors.panel-2}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "9px 11px"
  dialog-confirm:
    backgroundColor: "{colors.panel-2}"
    textColor: "{colors.ink}"
    rounded: "{rounded.frame}"
    padding: "22px 22px 18px"
---

# Design System: Vedette

## Overview

**Creative North Star: "The Drawing Set"**

Every page is a sheet in one set of technical drawings. Each NextDNS profile draws on its own layer in its own ink, so router reads teal and pc reads violet wherever they appear: the profile switch in the rail, the tables, the live feed and every chart. Every triage decision is entered as a revision in rose ink: a delta and its letter, the old status struck through, the new status and its time. Nothing is erased; the record only grows.

The ground is graphite, cool and near neutral, dark only. The rail is the darkest stock, the sheet one step lighter, panels one to three steps above that. Hairlines divide everything inside a sheet; a heavier frame rule runs only round each sheet's title block, which states what the sheet shows, which profiles, when it was drawn and its place in the set. Charts carry a drafter's furniture: a dimension line over the span drawn, finding markers with leaders down to their moment, break marks where a bar runs off the capped scale. The density is an operator's instrument: 14px body, tight tables, many figures, all tabular, read in short triage visits or left open all day as a live monitor.

Mona Sans is the set's own voice, widened for titles and the title block. JetBrains Mono carries data, and its italic marks every name that came from outside (a domain, a device name), so text an attacker controls is always visibly someone else's words. Confirmed refusals: KPI tiles over a grey table, a neon HUD, a generic admin template, a navy ground.

**Key Characteristics:**
- Graphite, dark only; tonal steps for depth, hairlines for structure.
- One ink per profile layer, fixed by its position in the configuration, identical on every surface.
- Rose revision ink for decisions and for what still waits for one; old states struck, never erased.
- Square frames (2px), a heavier frame rule only round the title block.
- Mona Sans expanded for titles; JetBrains Mono for data, its italic for every outside name; tabular figures throughout.
- Every control drawn in the set's own ink: select, checkbox, switch, segmented control, dialog, sort headings.
- Every page works without JavaScript under a strict CSP.

## Colors

A graphite ramp carries every surface, line and ink; colour is reserved for layer inks, revision rose and severity.

### Primary
- **Revision Rose** (`rev`): the owner's hand. A decision drawn as a revision (delta, letter, struck old status, new status), the open-findings count in the navigation and the switch, the lead's "needs a decision" count, open finding markers on charts, a fresh finding's wash (`rev-wash`), a figure that just changed (a one-shot flash), the text caret, selection and a switched-on switch. Text on a rose fill uses `on-rev`.

### Secondary
- **Router Teal** (`layer-1`) and **PC Violet** (`layer-2`): the two profile layer inks, assigned by each profile's position in the configuration. Their `-dim` partners draw that profile's blocked queries in stacked charts.
- **Spare Inks** (`layer-3` lime, `layer-4` stone): reserved for a third and fourth profile, in hues no severity or status colour uses, so a new profile never reads as a priority.
- **Neutral Layer** (`layer-0`, `layer-0-dim`): anything that belongs to no single profile, and the server-drawn chart before the interactive one loads.

### Tertiary
- **Severity chips**: critical red, high orange, medium amber, low blue, info grey; each a foreground, a near-black tinted background (`-bg`) and a border (`-line`).
- **Status** (`ok`, `warn`, `problem`): pipeline state, the live dot, health rows (`warn` for a passing check that is retrying or catching up), login errors. `warn` and `problem` share their values with medium and critical.

### Neutral
- **Rail Graphite** (`rail`): the navigation rail and the bare login/error pages.
- **Ground Graphite** (`ground`): the html ground and scrollbar track.
- **Sheet Graphite** (`sheet`): the working area behind every panel; also the halo cut round chart lines and break marks.
- **Panel Graphite 1-3** (`panel`, `panel-2`, `panel-3`): containers, then controls and hover, then current/pressed states and decided chart markers.
- **Hairline** (`line`), **Strong Hairline** (`line-strong`), **Ink Line** (`line-ink`): row and panel dividers, table head rules and control borders, then open/hover control borders and the dimension line.
- **Frame** (`frame`): only the rule round the title block.
- **Ink 1-3** (`ink`, `ink-2`, `ink-3`): text and primary fills, secondary text, labels and quiet figures.
- **Chart furniture** (`usual`, `band`, `now-wash`): the dashed usual-traffic line, its band, and the current period's wash.

### Named Rules
**The One Layer, One Ink Rule.** A profile's ink comes from its position in the configuration and is the same on every surface: rail switch, title block, table, feed row, chart series, legend, leader. Layer inks are never decoration and never severity.

**The Revision Ink Rule.** Rose means a decision, something waiting for one, or the owner's own hand (caret, selection, a switch they turned on). It is never used for severity, branding beyond the brand mark's one stroke, or emphasis.

**The Graphite Rule.** Neutrals are cool, near-neutral graphite, never navy and never pure black; depth comes from the next graphite step, not from a hue.

## Typography

**Display Font:** Mona Sans (with system-ui, Segoe UI, Roboto), variable width 75-125%, self-hosted
**Body Font:** Mona Sans
**Label/Mono Font:** JetBrains Mono (with ui-monospace, Cascadia Mono, Consolas), upright and italic, self-hosted

**Character:** A wide, engineered grotesque for the set's own words against a drafting mono for every figure, time and name; the mono italic is a typographic quarantine for outside text.

### Hierarchy
- **Display** (640, 30px, 1.1, width 122%): the title block's sheet title; 26px on phones. The login title uses 650, 24px, width 120%.
- **Headline** (620, 17px, width 110%): each block's heading on a sheet.
- **Title** (620, 15px): panel headings; chart dialog title 18px, width 112%; confirm title 16px, width 110%.
- **Summary** (400, 17px, 1.55, max 72ch): the model's reading at the top of a finding's explanation.
- **Body** (400, 14px, 1.5): everything else; the lead under a title is 15px, max 76ch.
- **Label** (400, 12px, ink-3): field labels, title-block field names, table headings (520), hints, legends.
- **Data** (JetBrains Mono, 12-13px): times, figures, counts, finding numbers (printed four digits), chart axes (11px).
- **Chip** (JetBrains Mono 620, 11px): severity badges and status chips.

### Named Rules
**The Outside Words Rule.** Every name that came from outside (domain, device) is set in JetBrains Mono italic, escaped and defanged, and is never a link.

**The Tabular Rule.** Figures are tabular everywhere (`font-variant-numeric: tabular-nums` on the root); numeric columns align right.

**The Eleven Pixel Floor Rule.** No text below 11px, including canvas text in charts.

## Layout

A fixed 252px rail on the left (220px between 641 and 1180px) and the sheet beside it, padded 26px top and 40px sides (28px on tablets, 16px on phones), up to 3200px wide. Each sheet opens with its title block, then blocks stacked 34px apart, each with a 17px heading 12px above its panel. Panels pad 16px by 18px; columns sit 32px apart.

Responsive behaviour: at 1180px and under, the title block's fields drop below the title and two-column boards stack. At 860px the rail becomes a top bar: brand and sign-out, then the profile switch as a full-width row, the pipeline line, then the page links as a horizontally scrolling row that fades out at its right edge. At 640px findings become stacked cards with full-width, equal action buttons. Wider than 2240px, what sat in rows becomes columns: Overview goes two-column (2fr and a 460px-minimum side), Live puts the feed and chart side by side, a finding's detail goes to a two-column main plus a 400px side.

The findings table narrows by container query rather than viewport: under 1180px of container it drops the Events column, under 1000px it folds the secondary columns into one line under the finding, so the decision buttons stay in view without horizontal scrolling. The live feed keeps a fixed eight-row height in its compact form so a new row never moves what sits below it.

## Elevation & Depth

Flat by default. Depth is tonal: rail, sheet and three panel steps. Structure is hairlines. One shadow exists, and it only lifts what floats over the sheet.

### Shadow Vocabulary
- **Lift** (`box-shadow: 0 18px 40px -12px rgb(0 0 0 / 0.6), 0 2px 6px rgb(0 0 0 / 0.3)`): the select's listbox, the confirm dialog, the enlarged chart dialog. Dialog backdrops are `rgb(5 5 6 / 0.8)`.

### Named Rules
**The Lift Only Floats Rule.** A shadow means the layer floats over the sheet (a menu or a dialog). Panels, cards, buttons and chips never carry one.

**The Frame Rule.** The title block alone carries the heavier 1.5px `frame` rule, with a 1px `frame` rule between its title and fields; everything inside a sheet is a 1px hairline.

## Shapes

Square drawing frames. Panels, tables, the title block, menus and dialogs use a 2px radius; controls (buttons, selects, inputs, layer options, page links) use 3px; inner items (segment buttons, menu options, severity and status chips, the navigation count, code and kbd) use 4px. Round shapes are kept for things that are round in a drawing set: the live status dot, the switch track and knob, and the 2px-rounded ink marks (layer marks 16 by 4px, legend keys) that stand for a pen stroke. Icons are drawn SVG strokes, 1.5px, round caps and joins, in `currentColor`.

## Components

### Buttons
- **Shape:** gently squared (3px).
- **Default:** `panel-2` fill, `line-strong` border, 560 weight 13px, 7px by 12px; hover steps to `panel-3` and a `line-ink` border; press nudges 0.5px down.
- **Primary:** an `ink` fill with `sheet` text, for the single decision on a finding's page and confirm dialogs; hover goes to white. In a findings table the primary is drawn in outline (`ink-2` border, transparent), so a column of identical buttons never outshouts the revisions.
- **Quiet:** transparent, `ink-2` text; hover takes `panel-2`.
- **Link button:** rose, underlined, no frame; an inline action inside a sentence, such as showing the new rows a paused feed has held back.
- **Disabled:** 50% opacity, not-allowed cursor.

### Chips
- **Severity badge:** mono 620 11px, 2px by 7px, 4px radius, the severity's tinted background, border and foreground. Decided rows dim their badge to 70%.
- **Status chip:** outlined in `line-strong`, `ink-2` text; a blocked chip takes `line-ink` and `ink`.

### Cards / Containers
- **Panel:** `panel` fill, 1px `line` border, 2px radius, 16px by 18px. No shadow.
- **Title block:** `panel` fill, 1.5px `frame` border; the title and lead on the left, a row of fields on the right (Showing, with the layer mark; any page figures; Drawn; Sheet), each field a 12px `ink-3` label over a 14px value.
- **Findings on phones:** each row becomes a bordered `panel` card with the decision on its own line and equal-width actions.

### Inputs / Fields
- **Select (listbox):** the native select stays in the form and is replaced by a drawn button with a chevron that turns 180 degrees when open; the list drops 5px below (or opens upward near the viewport foot) on `panel-2` with a `line-ink` border and the lift shadow, the active option on `panel-3`, the chosen one in 600 with a check.
- **Checkbox:** the real input stays for keyboard and screen readers; a 15px drawn box with a `line-ink` border fills with `ink` and draws a `sheet` tick when checked.
- **Switch:** a 30 by 17px track; when on, the border and knob turn rose over `rev-wash`.
- **Text field:** `panel-2`, `line-strong` border, mono 14px; focus moves the border to `line-ink` with a 2px `panel-3` ring; invalid takes a `problem` border.
- **Focus:** every focusable element shows a 2px `ink` outline, 2px offset.
- **Folded filters:** at 860px and narrower the Findings filters sit behind one `panel-2` control reading "Filters" with a drawn chevron and, in rose mono, how many filters are set; opened, the filters panel sits 10px under it. Above 860px the control is not shown. Without JavaScript the filters stay open.

### Navigation
- **Rail:** the brand (a 24px squared mark with three strokes: teal, violet, rose; the name in Mona Sans at 112% width), the profile switch, the page links, and the pipeline state at the foot.
- **Profile switch:** a `panel` box listing Both, then each profile with its layer mark and its open count in rose (`ink-3` when zero); the current option sits on `panel-3` with a `line-ink` border. Choosing a layer re-inks every sheet.
- **Page links:** `ink-2`, hover on `panel`, current on `panel-2` in 600, with a rose count chip (grey when zero).

### Sortable Table Headings
The heading itself is the button; a drawn two-chevron sort icon at 45% shows the available directions, the active chevron goes full `ink` and the other drops to 20%; `aria-sort` carries the state. Rows divide with `line`, hover takes a 70% `panel-2` wash, numeric columns align right in mono.

### Segmented Control
A `panel` tray with a 2px inner padding; segments are transparent `ink-2`, the current one on `panel-3` with a `line-ink` border. Used for time ranges and views.

### Revision Mark (signature)
A decision is a revision: a small rose delta, its letter, the old status struck in `ink-3` with a 2px rose strike, then the new status and its mono time. In a table it takes two lines. When a decision lands, the revision inks in left to right over 560ms; a newly arrived finding settles out of a rose wash over 2.4s. On a finding's page the revisions list each entry beside a numbered delta outline.

### Interactive Chart (signature)
Per-profile stacked layers in each profile's ink, its blocked share in the dim ink; legend checkboxes turn layers on and off. A dimension line (ticked extension lines either side of the mono span) sits over the plot; a two-line readout above the plot holds its height so the plot never moves under the pointer. Finding markers sit at the top as rose tags (open) or `panel-3` tags (decided) with dashed leaders down in the profile's ink. A bar past the capped scale is cut by a break mark, two slashes in the sheet's colour, with its real value above. The dashed `usual` line shows normal traffic. The server draws an SVG version first and without JavaScript.

### Finding Explanation
The model's summary first (17px, 72ch), then likely cause and recommended action side by side in a bordered grid (the action cell one step lighter), each headed by a drawn 16px icon, then a facts row with a confidence meter (100 by 6px), priority and who decides. Under a hairline, "What the rule checks" in 12px `ink-3` and the rule's description in 13.5px `ink-2`, on every finding. A finding is titled by its rule's plain name; the rule id is a mono field in the title block, and a NextDNS reason shows by name with its id after it in 12.5px mono `ink-3`.

The Decision panel is drawn twice and only one shows: beside the record above 1,180px, directly after the explanation at 1,180px and narrower.

### Confirm Dialog
A 460px `panel-2` dialog with a `line-ink` border and the lift shadow, rising 8px into place over 200ms. The title names the action as a question ("Mark this finding benign?"); the body in `ink-2` sets the domain as an outside name and says how to undo it. Focus opens on Cancel; the confirming button carries the action's own label. Actions right-aligned.

## Do's and Don'ts

### Do:
- **Do** draw every profile in its layer ink (`layer-1` teal, `layer-2` violet by configuration position) on every surface that names or plots it, and its blocked queries in the `-dim` partner.
- **Do** enter every triage decision as a revision: rose delta, letter, old status struck, new status, time.
- **Do** head every sheet with the title block (title, lead, Showing, Drawn, Sheet) inside the 1.5px `frame` rule.
- **Do** set every outside name (domain, device) in JetBrains Mono italic, escaped and defanged, as plain text.
- **Do** keep figures tabular and in mono, and text at 11px or larger.
- **Do** draw every control in the set's ink: the custom select, drawn checkbox and switch, segmented control, sort headings, and dialogs, with the native element kept for keyboard, screen readers and no-JavaScript use.
- **Do** keep every page usable without JavaScript and within a strict CSP: no inline styles or scripts, nothing external, fonts self-hosted.
- **Do** honour reduced motion: transitions collapse, the revision appears already inked, dialogs and menus appear without animation.

### Don't:
- **Don't** use rose for severity, decoration or emphasis; it belongs to decisions and the owner's hand.
- **Don't** use a layer ink for anything that is not that profile.
- **Don't** add shadows to panels, cards, buttons or chips; only menus and dialogs lift.
- **Don't** build KPI tiles over a grey table, a neon HUD with glows, or a generic admin template.
- **Don't** move to a navy or pure-black ground, or add a light theme; the set is graphite and dark only.
- **Don't** make an outside name a link, or render it in the sans.
- **Don't** erase a decision; a reopened finding shows "open" with its revision under it.
