# NextDNS Sentinel dashboard: the order of findings

## Navigation Specification

Every list of findings opens in triage order: highest priority first, and within a priority the most recently seen first. Priority is the effective one, the rule's floor or the model's raise. The order is the same on the Findings page, the Overview's "Needs a decision", and J and K on a finding's page, so stepping with J follows the list the owner just left [src/sentinel/storage/dashboard.py, `neighbours`].

The Priority heading shows the sort on load. Any heading re-sorts the table in place; a sort the owner picks holds while the filters change, and the default returns with a reload.

The Findings page lists at most the 200 most recently seen findings that match its filters, and puts those 200 in triage order.

Digests and the Live feed stay in time order: a digest reports a period, and the feed shows queries as they arrive.
