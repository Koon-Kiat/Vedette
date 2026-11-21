# Vedette dashboard copy: rule names, confirmations, health and errors

## Terminology

| Term | Meaning to the owner | Not |
|---|---|---|
| Rule name | What a rule detects, in plain words; the title of every finding the rule raises. | detector, check type |
| Rule id | The rule's fixed reference, as Discord alerts, the digest, config.yaml and `vedette findings` print it. Shown beside the name, set as data. | slug, key |
| What the rule checks | The rule's description from rules.yaml: what it looks for and why that matters. | definition, help text |
| Reason | The NextDNS category or blocklist attached to a query, by the name NextDNS gives it; its id (`native:<vendor>`, `ads`) is secondary. | category id |
| Rate limit | NextDNS refusing requests for a while because Vedette asked too often. | HTTP 429, rateLimit |

## Copy Deck

### Rule names

Shown as the finding's title on its page, in the Rule column of every findings table, in the rule filter and in chart marker labels. The id follows the name in data type wherever the name is a title.

| Rule id | Rule name |
|---|---|
| `new-device` | New device |
| `young-domain` | Newly registered domain |
| `threat-intel-allowed` | Threat-feed domain allowed |
| `dga-like` | Random-looking domain name |
| `tunnel-like` | Possible DNS tunnelling |
| `volume-spike` | Query volume spike |
| `blocked-burst` | Burst of blocked queries |
| `new-destination-category` | New category or blocklist |

A rule with no name set (a rule added later) shows its id in the name's place.

**Finding page, under the explanation, every finding:** "What the rule checks" as a label, then the rule's description from rules.yaml. Replaces the description shown only for findings not analysed yet.

### Alerts and the digest

| Where | String |
|---|---|
| Alert title | {PRIORITY}: {rule name}, {about} ({profile}) |
| Alert rule line | Rule: {rule name} ({rule id}), severity floor {floor} |
| Alert footer | Finding #{id}. More: vedette findings --rule {rule id} |
| Digest entry, first line | {n}. {PRIORITY} {rule name}: {about} ({profile}, {device}) |
| Digest entry, last line | {Explained by {model}. / Not explained by the local model.} Rule: {rule id}. |

`{about}` is the reason's name for a new-category-or-blocklist finding, as on the dashboard.

### Mark benign confirmation

Trigger: Mark benign on a finding whose rule allowlists its domain (young-domain, threat-intel-allowed, dga-like, tunnel-like).

| Part | String |
|---|---|
| Title | Mark this finding benign? |
| Body | Vedette stops flagging *{domain, defanged}* on {profile}. Reopen the finding to undo this. |
| Confirm button | Mark benign |
| Cancel button | Cancel |

`{domain}` is set as an outside name. `{profile}` is the profile's label.

### Health: NextDNS API check

`{phrase}` comes from the status NextDNS answered:

| Status | `{phrase}` |
|---|---|
| 429 | NextDNS is rate-limiting Vedette |
| 401, 403 | NextDNS refused the API key |
| 500 and above | NextDNS answered with a server error |
| anything else | the recorded reason, unchanged |

| State | Detail |
|---|---|
| Retrying, inside the error window | {phrase} since {HH:MM}. Vedette waits and tries again. |
| Failing, past the error window | NextDNS API failing for {duration} ({profile}): {phrase} (HTTP {status}) |

The failing string is also the Discord health alert, so the status code stays at its end for diagnosis.

### Reason names

A new-category-or-blocklist finding shows the reason's name where the evidence recorded one, with the id after it in data type on the finding's page: *Ads and trackers* `ads`. A finding with no recorded name shows the id.

### Error pages

| Status | Title (heading and browser tab) | Body (unchanged) |
|---|---|---|
| 404, finding | Finding {0000} not found | There is no finding {0000}. Findings are deleted once they are older than the retention period, so a link from an old digest or alert can outlive its finding. |
| 404, other | Page not found | That page does not exist. |
| 403 | Page out of date | The page was out of date. Reload it and try again. |
| 400 | Request not valid | {the request's own message}, such as "The login form expired. Load it again." |
| 405 | Not allowed | That is not allowed here. |
| 422 | Request not valid | {the request's own message} |
| 429 | Too many live views | Too many live views are open. Close one and reload. |

The status code stays in the title block's fields as "Status {code}".

