# NextDNS Sentinel dashboard: open counts after a decision, and a retrying API check

## State Inventory

### Every page

| State | Where | What the owner sees | What they can do | Recovery and timings | Severity |
|---|---|---|---|---|---|
| Counts after a decision | Profile switch, menu Findings count, Overview "All open findings" link | Every open-findings count changes with the decision's response: the profile's own count and Both drop by one on Acknowledge or Mark benign of an open finding, and rise by one on Reopen. | Keep triaging; the counts agree on every surface. | The decision's response carries the new counts and replaces each count in the same swap as the row. The live stream sends every profile's count whenever any open count changes, within its one-second poll, so a decision made in another tab or by the CLI reaches this page too. A count that reaches zero takes the existing zero style. | Minor |
| Counts while the live stream is down | Same counts | The counts as of the last decision made on this page or the last stream message. | Reload the page. | The pipeline status already says the live view is reconnecting; counts catch up on the stream's next message after it reconnects. | Cosmetic |

### Health

| State | Where | What the owner sees | What they can do | Recovery and timings | Severity |
|---|---|---|---|---|---|
| Retrying | NextDNS API check, inside `api_error_minutes` of the first error | State column "Retrying" in the warning colour. Detail as in docs/ux/copy-dashboard.md (Health: NextDNS API check), with the time of the first error in the dashboard's time zone. | Nothing is needed; the check settles on its own. | Clears to "OK" on the next successful request. Past `api_error_minutes` it becomes "Problem" and the health alert goes out, as today. Counts as passing in the menu's "checks OK" line, because no alert has been raised. | Minor |
| Catching up | Events check for a profile, in the first ten minutes after Sentinel starts, while the collector reads what the profile sent meanwhile | State column "Catching up" in the warning colour; detail "Catching up after start-up". | Nothing is needed. | Clears to "OK" once the profile's newest event is recent, or to "Problem" when the grace ends without catching up. Counts as passing in the menu. | Minor |
