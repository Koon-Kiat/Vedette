# Security

Vedette reads DNS logs, which anyone can fill with names of their choosing,
and shows them to a local language model and a dashboard. Problems in how it
handles that text matter, and reports are welcome.

## Reporting a vulnerability

Report it privately through GitHub: on this repository's **Security** tab,
choose **Report a vulnerability**. Please do not open a public issue, pull
request or discussion about it first.

Include what you did, what happened, and what you expected, with the smallest
input that shows it (a crafted domain or device name, a log entry, a request).
Leave out real DNS history, API keys and webhook URLs; synthetic names under
`.example` are enough.

This is a personal project, maintained on a best-effort basis. There is no bug
bounty. A report will be acknowledged, and a fix, or the reason there is none,
recorded in the changelog.

## What counts

- A crafted name or log entry that lowers a finding's priority below its
  rule's floor, hides a finding, or gets the model's text shown as HTML, a
  link or markup.
- Script running in the dashboard, a write without the session's CSRF token,
  or the dashboard answering on an address other than `127.0.0.1`.
- A secret (`NEXTDNS_API_KEY`, `DASHBOARD_TOKEN`, a notification secret)
  reaching a log line, an alert, a digest or an error message.
- A way for the `ollama` container to reach the internet, or for either
  container to gain privileges it was not given.

The risks Vedette accepts are listed under "Residual risk" in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md); a report that one of them is
worse than described there is welcome too.

## Supported versions

Only the latest commit on `main`.
