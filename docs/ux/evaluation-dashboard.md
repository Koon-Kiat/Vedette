# Vedette dashboard, the drawing set, every page

## Anti-Pattern Verdict

Clean.

## Priority Issues

### Minor

**Findings are named by their rule's id**
- **What happens:** A finding's page is headed by its rule id ("young-domain"), and the Findings table, the rule filter and the Overview use the same ids ("threat-intel-allowed", "new-destination-category"). What the rule checks appears only while the model has not explained the finding [/findings/2; src/vedette/web/templates/finding.html; src/vedette/rules/rules.yaml].
- **Why it matters:** At the moment of decision the owner reads a code name for what was detected and has no plain statement of what the rule looks for.
- **Breaks:** match between system and the real world.
- **Change:** Give each rule a plain name and use it as the finding's title everywhere, keep the id as a secondary reference that matches the Discord alerts, and show what the rule checks on every finding's page.

**The profile switch keeps old counts after a decision**
- **What happens:** After the only open router finding was acknowledged, the menu's Findings count fell from 4 to 3, while the profile switch still read "Both 4 open" and "router 1 open" until the page was reloaded [/findings, synthetic data].
- **Why it matters:** Two counts of the same findings disagree on the screen where the decision was made, so the owner cannot tell whether it counted.
- **Breaks:** visibility of system status; consistency and standards.
- **Change:** Refresh every open-findings count, the switch's included, whenever a decision is made and whenever the live counts update.

**Mark benign's confirmation starts on the confirming button**
- **What happens:** The dialog opens with focus on "Mark benign", is titled "Please confirm", and does not say that Reopen removes the allowlist entry it creates [/findings, synthetic data; src/vedette/storage/triage.py, `reopen`].
- **Why it matters:** Enter pressed twice allowlists the domain on that profile and silences its future alerts, and the owner is not told the step can be undone.
- **Breaks:** error prevention; user control and freedom.
- **Change:** Open the dialog on Cancel, title it with the action and the domain, and say that Reopen undoes it.

**Health reports "OK" beside an error message**
- **What happens:** Both NextDNS API checks read "OK" in the State column and "Recent errors: NextDNS answered HTTP 429 (rateLimit)" in the Detail column [/health, real data].
- **Why it matters:** On the page meant to answer whether the pipeline needs attention, the owner cannot tell whether this check does, and the detail is a status code and an API keyword.
- **Breaks:** match between system and the real world; help users recognize, diagnose, and recover from errors.
- **Change:** Say in words that NextDNS asked Vedette to slow down, when that last happened, and that collection continued.

**Findings lists newest first, the Overview highest priority first**
- **What happens:** Findings sorts by Last seen, so a critical finding sits below a medium one seen later; the Overview's "Needs a decision" sorts by priority [/findings, /, synthetic data].
- **Why it matters:** On the page built for triage, the most serious open finding stops being the first one seen once there are more than a few.
- **Breaks:** consistency and standards.
- **Change:** Order Findings by priority and then by time, as the Overview does, with the headings still re-sorting.

**On a narrow window the decision is screens away**
- **What happens:** On a finding's page at 375 pixels the Decision panel starts 1,978 pixels down a 2,595-pixel page, after the evidence, the caches and the recent queries. On Findings the five filters fill the first screen [/findings/2 and /findings at 375 × 812, real data].
- **Why it matters:** With the dashboard in a narrow window beside other work, the action the visit exists for is the hardest thing to reach.
- **Breaks:** aesthetic and minimalist design.
- **Change:** At narrow widths place the Decision directly after the explanation, and fold the filters behind one control that shows how many are set.

**NextDNS reason ids appear raw**
- **What happens:** A new-destination-category finding shows its NextDNS reason id, in the form `native:<vendor>`, in the About column and as its title [/findings, real data].
- **Why it matters:** The owner reads an internal identifier where NextDNS has a name for the category or blocklist.
- **Breaks:** match between system and the real world.
- **Change:** Show the reason's name where it was recorded, with the id kept as the secondary reference.

### Cosmetic

**The table moves under the pointer after a decision**
- **What happens:** When a row's status changes to a revision, every column changes width, and the next row's buttons shift sideways [/findings, synthetic data].
- **Why it matters:** The button the owner was about to press moves just after a click.
- **Breaks:** consistency and standards.
- **Change:** Give the status and action columns room for a revision so a decision changes no column's width.

**The error page is titled "404"**
- **What happens:** The heading and the browser tab read "404", and the page has no title block, unlike every other sheet [/findings/99999].
- **Why it matters:** A link from an old digest lands on a page named by a status code.
- **Breaks:** match between system and the real world; consistency and standards.
- **Change:** Title the page with what was not found, in the set's title block.

**Outside names lose their marking in the evidence and the dialog**
- **What happens:** Domain names in "Evidence when it fired" and in the Mark benign dialog are set in the body face; tables and the feed set them in the italic monospace that marks text from outside [/findings/2, synthetic dialog].
- **Why it matters:** The one visual signal that says "this text came from the network" disappears where the owner makes the decision.
- **Breaks:** consistency and standards.
- **Change:** Mark every outside name the same way.

**Domain names break mid-word**
- **What happens:** In the side-by-side Domains tables, longer names wrap inside a label [/domains at 1,440 × 900, real data].
- **Why it matters:** A name split at an arbitrary letter is harder to read and compare.
- **Breaks:** aesthetic and minimalist design.
- **Change:** Break long names only at their dots.

**Usual query counts show tenths of a query**
- **What happens:** "Today against the usual week" reads 30,219.7 usual queries for a profile [Overview, real data].
- **Why it matters:** The decimal adds precision a daily average of tens of thousands does not have.
- **Breaks:** aesthetic and minimalist design.
- **Change:** Round the usual query counts to whole queries.

## Positive Findings

- A decision swaps its row in place, keeps focus on the next action and is announced.
- Mark benign asks before it allowlists, and Reopen removes the entry it created.
- One profile switch scopes every page, and each profile keeps one ink on every surface.
- The finding's page states that the rule set the floor and the model can only raise it.
- Every outside name is defanged and never a link.
- A missing finding keeps the menu and says findings are deleted after the retention period.
- The skip link is the first stop, the custom lists work with the arrow keys, and J and K step through open findings.
- The charts zoom, pan and enlarge from the mouse and the keyboard, and the enlarged view closes with Escape and returns focus.
