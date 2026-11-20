# NextDNS Sentinel dashboard, every page

## Anti-Pattern Verdict

Clean.

## Priority Issues

### Major

**The triage buttons are cut off at common laptop widths**
- **What happens:** Between 1,181 and about 1,400 pixels the findings tables show every column and overflow, so Acknowledge and Mark benign sit behind a horizontal scrollbar: 1,047 pixels of table in 953 on the Overview, 1,121 in 966 on Findings [Overview and /findings at 1,280 × 800].
- **Why it matters:** On a 1,280-pixel laptop, the most common triage screen, the decision the visit exists for is out of sight.
- **Breaks:** visibility of the action that completes the task, at the decision step of the triage walkthrough.
- **Change:** Fold the secondary columns whenever the table is narrower than it needs, judged by the table's own width rather than the window's.

**After an upgrade the browser keeps the old stylesheet**
- **What happens:** Static files were sent with no caching rule, so the browser kept a day-old copy of the stylesheet and script and reused it with new pages; a hard reload did not replace it. The new menu link then sat in the page grid and pushed the whole page into the menu column [Overview after an upgrade, Chromium].
- **Why it matters:** The first visit after every upgrade can show a broken page until the cache expires on its own.
- **Breaks:** consistency and standards; visibility of system status.
- **Change:** Give each of the dashboard's own static files a URL that changes with its content, and have the browser check static files on every load.

**The live feed puts late queries on top of newer ones**
- **What happens:** Queries that reach the collector a minute or two late are added at the top, so "Right now" read 10:59:01 above 11:01:01 [Overview, real data].
- **Why it matters:** A feed that claims to show what is happening now shows older queries as the newest.
- **Breaks:** visibility of system status; match between system and the real world.
- **Change:** Place each arriving query by its own time, newest first.

**Focus is lost after a triage decision**
- **What happens:** After Acknowledge, Mark benign or Reopen, the row is replaced and keyboard focus falls back to the page body; nothing is announced [/findings, synthetic data].
- **Why it matters:** A keyboard or screen-reader user loses their place in the list after every decision and has to tab back from the top, and is not told the decision was recorded.
- **Breaks:** visibility of system status; focus order.
- **Change:** Keep focus on the replaced row's first action and announce the decision in a polite status message.

**A finding's page contradicts itself**
- **What happens:** The explanation says the domain is not on the top-sites list and was registered 8 days ago; the caches below say it is on the list at a rank near 900,000 and was registered 16 days ago. The caches show today's facts without saying so, and the evidence table hides the empty rank that made the rule fire [/findings/2].
- **Why it matters:** At the moment of decision the owner cannot tell which facts are true, so the explanation loses its trust.
- **Breaks:** consistency and standards; match between system and the real world.
- **Change:** Mark the caches as today's facts, say where they differ from the moment the finding fired, and show an absent rank in the evidence.

**Devices says the laptop profile has no device attribution**
- **What happens:** The `pc` profile, silent for 20 days, gets "Device attribution unavailable on this profile: NextDNS reports no devices for it", although it reports device names when it sends queries [/devices; PRODUCT.md].
- **Why it matters:** The owner is told a working profile is misconfigured, which invites a needless change in NextDNS.
- **Breaks:** match between system and the real world; honest about gaps.
- **Change:** Say the profile sent no queries in the last 7 days, and keep the attribution notice for profiles that send queries without devices.

### Minor

**Health numbers are defanged like domain names**
- **What happens:** Disk space reads "935[.]5 GB free": the pipeline's own messages pass through the filter that brackets the dots in domain names [/health].
- **Why it matters:** A plain number looks like a defanged name, and the page reads as broken.
- **Breaks:** match between system and the real world.
- **Change:** Defang only names inside health details, never numbers.

**Evidence uses field names and NextDNS's word "default"**
- **What happens:** The evidence table lists `domain_age_days`, `fqdn`, `root` and `status: default`, and the recent queries say "default", while every other page says "allowed" [/findings/2].
- **Why it matters:** The owner reads database keys and a second word for "allowed" at the moment of decision.
- **Breaks:** match between system and the real world; consistency and standards.
- **Change:** Label evidence fields in words and show NextDNS's "default" as "allowed".

**The error page drops the navigation and names nothing**
- **What happens:** A finding that no longer exists, such as one purged after 180 days, gives "404 Not found." on a page without the menu, with one link back to the Overview [/findings/99999].
- **Why it matters:** A link from an old digest or alert ends in a dead end that does not say why.
- **Breaks:** help users recognize, diagnose, and recover from errors.
- **Change:** Keep the menu on error pages for a logged-in owner, and say what was not found and why it may be gone.

**The login error gives no next step and is not tied to the field**
- **What happens:** A wrong token shows "That token is not right." above the field; the field is not marked invalid or linked to the message [/login].
- **Why it matters:** The owner does not learn where the token lives or that it must match exactly, and a screen reader does not tie the message to the field.
- **Breaks:** help users recognize, diagnose, and recover from errors.
- **Change:** Link the message to the field, and say where the token is and that it must match exactly.

**Keyboard users pass the whole menu on every page**
- **What happens:** Each page starts with the menu, the pipeline status and Log out before the content, with no way to skip them [every page].
- **Why it matters:** Ten or more tab stops precede every triage action.
- **Breaks:** flexibility and efficiency of use.
- **Change:** Add a skip link to the main content as the first focusable element.

**A chart drawn in a narrow window keeps coarse bars after it widens**
- **What happens:** The check that fetches finer bars after a resize reads the chart's previous drawing size, so a chart first drawn narrow keeps its first bar count (60 bars on an 851-pixel plot) [Overview].
- **Why it matters:** The owner sees half-hour bars where the width allows five-minute ones, until the page is reloaded.
- **Breaks:** visibility of system status.
- **Change:** Judge the wanted bar count from the plot's container, not from the drawing.

**A quiet profile keeps the status red all day**
- **What happens:** The laptop profile, silent for 20 days, keeps "1 of 7 checks failing" in red in the menu on every page [/health; PRODUCT.md].
- **Why it matters:** Expected silence reads as a fault, so a real fault is easier to miss on a monitor left open all day. Each profile already accepts `stale_after_minutes` and `quiet_hours` in config.yaml, but nothing on the page says so [src/sentinel/config.py].
- **Breaks:** help and documentation.
- **Change:** On a failing silence check, name the profile settings that tell Sentinel the profile goes quiet.

**On a phone, Mark benign spills out of the finding card**
- **What happens:** The status took two grid columns, leaving the buttons too little room, so Mark benign ran past the card's edge [/findings at 375px].
- **Why it matters:** The decision buttons look broken where triage on the go happens.
- **Breaks:** aesthetic and minimalist design.
- **Change:** Give the status only the room it needs and let the buttons wrap within the card.

**On a phone, the Today table runs past its panel**
- **What happens:** The five-column comparison is wider than the screen and its last column is cut off at the edge [Overview at 375px].
- **Why it matters:** The usual blocked share, the column that tells whether today is normal, cannot be read.
- **Breaks:** visibility of system status.
- **Change:** Let the table scroll sideways inside its panel.

### Cosmetic

**The live pill floats, with a wide gap after "Live"**
- **What happens:** The pill spanned both header rows and bottom-aligned, so its text sat on neither the title's line nor the lead's; inside it, "Live" and the figures were as far apart as the dot and "Live" [Overview and Live, real data].
- **Why it matters:** The page's one live signal looks misplaced.
- **Breaks:** aesthetic and minimalist design.
- **Change:** Centre the pill on the title's line and mark the split between state and figures with a hairline.

**The live line says "1 queries"**
- **What happens:** The noun did not follow the count [/live, real data].
- **Why it matters:** Small grammar slips cost trust in the numbers beside them.
- **Breaks:** consistency and standards.
- **Change:** Match the noun to the count as the figure updates.

**Chart legends break inside a label**
- **What happens:** On a narrower chart "open finding" split across two lines [/live at 900px].
- **Why it matters:** A key separated from half its label is hard to read.
- **Breaks:** aesthetic and minimalist design.
- **Change:** Keep each key with its label and wrap between items.

**The y-axis rounds its ticks**
- **What happens:** A tick at 1,250 read "1.3K" [Overview, real data].
- **Why it matters:** The grid line and its label disagree.
- **Breaks:** match between system and the real world.
- **Change:** Show compact ticks to two decimals.

**The Overview lead ends with a note about another section**
- **What happens:** The lead reads "N findings need a decision. Last 24 hours, compared with the 7-day average.", the second sentence describing the table at the bottom of the page [Overview].
- **Why it matters:** The fragment reads as part of the decision count.
- **Breaks:** aesthetic and minimalist design.
- **Change:** Move the period note to the heading of the table it describes.

**The Domains registration column is almost all "unknown"**
- **What happens:** Registration dates are looked up only for new, little-known domains, so nearly every row reads "unknown" [/domains].
- **Why it matters:** A column of repeated words hides the few dates that matter.
- **Breaks:** aesthetic and minimalist design.
- **Change:** Show a quiet dash for dates never looked up, and say in the page's lead which domains get looked up.

**The digest empty state does not say when**
- **What happens:** "The first one is produced at the next digest time." [/digests]
- **Why it matters:** The owner has to look up the configured time.
- **Breaks:** visibility of system status.
- **Change:** Name the digest time.

**A plural is wrong on the Evaluation page**
- **What happens:** "1 high or critical findings over 19.9 days" [/evaluation].
- **Why it matters:** Small grammar slips cost trust in the numbers beside them.
- **Breaks:** consistency and standards.
- **Change:** Match the noun to the count.

## Positive Findings

- Every decision is reversible in place: the row swaps to the new status with a magenta correction and a Reopen button.
- Mark benign asks before it allowlists, naming the domain and the profile.
- The finding's page says plainly that the rule set the floor and the model can only raise it.
- Every outside name is defanged, set apart in sloped type, and never a link.
- The menu's pipeline status answers "is it alive" on every page.
- Empty states say what will fill them and when work will appear.
- The charts work fully from the keyboard and announce what changes.
- No page scrolls sideways on a phone, and ultrawide screens get side-by-side layouts.
