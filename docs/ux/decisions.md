## 2026-11-20 · The dashboard evaluation reads the owner's real data and changes nothing in it
- Decided by: Claude (default)
- Why: triage actions write to the audit log, so Acknowledge, Mark benign and Reopen were exercised on the synthetic preview instead.
- Rejected: deciding and reopening a real finding, which would leave entries in the owner's history.
- Rests on: PRODUCT.md, Evidence on Hand.

## 2026-11-20 · The evaluation covered Chromium only, with no assistive technology
- Decided by: Claude (default)
- Why: the built-in browser is Chromium; screen-reader behaviour was judged from the accessibility tree and focus, not with NVDA or JAWS, and touch from emulated phone widths, not a device.
- Rejected: claiming screen-reader or Safari coverage.
- Rests on: docs/ux/evaluation-dashboard.md.

## 2026-11-20 · A failing silence check points at the existing profile settings instead of changing the check
- Decided by: Claude (default)
- Why: `stale_after_minutes` and `quiet_hours` already exist per profile; whether the laptop's long silence is a fault is the owner's call, and the check also drives alerts.
- Rejected: silencing the check by default, or a new "expected quiet" setting.
- Rests on: src/sentinel/config.py, ProfileConfig; docs/ux/context-nextdns-sentinel.md, Open questions.

## 2026-11-20 · The login form keeps autocomplete off
- Decided by: Claude (default)
- Why: the existing form asks browsers not to store the token; the evaluation fix ties the error to the field without reopening that security choice.
- Rejected: marking the field as a current password so a password manager can fill it.
- Rests on: src/sentinel/web/templates/login.html.

## 2026-11-20 · Our static files carry a content hash in their URL and are revalidated on every load
- Decided by: Claude (default)
- Why: a browser reused a day-old stylesheet with new pages and broke the layout; a hard reload did not clear it.
- Rejected: long-lived caching, and relying on the no-cache header alone.
- Rests on: docs/ux/evaluation-dashboard.md, "After an upgrade the browser keeps the old stylesheet".
