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

## 2026-11-21 · The drawing-set evaluation read a disposable copy of the owner's database
- Decided by: Claude (default)
- Why: the pages were read against real volumes and real findings without touching the live database or the owner's login; triage was exercised on synthetic data.
- Rejected: swapping the live dashboard's token, which ends the owner's session.
- Rests on: docs/ux/evaluation-dashboard.md.

## 2026-11-21 · The drawing-set evaluation covered Chromium, mouse, keyboard and emulated widths only
- Decided by: Claude (default)
- Why: the built-in browser is Chromium; screen-reader behaviour was judged from roles, names and live regions, not with NVDA, and narrow layouts from an emulated 375-pixel width.
- Rejected: claiming screen-reader, Firefox or Safari coverage.
- Rests on: docs/ux/evaluation-dashboard.md.

## 2026-11-21 · Rules get plain names; the id stays beside them
- Decided by: Claude (default)
- Why: a finding's title was its rule id; Discord alerts, the digest, config.yaml and the CLI print the id, so it stays visible as the reference that matches them.
- Rejected: replacing the id everywhere, which breaks the match with alerts; leaving ids as titles.
- Rests on: docs/ux/evaluation-dashboard.md, "Findings are named by their rule's id"; docs/ux/copy-dashboard.md, Rule names.

## 2026-11-21 · Mark benign's confirmation opens on Cancel
- Decided by: Claude (default)
- Why: the action silences the domain's future alerts on that profile; two presses of Enter should not do that.
- Rejected: focus on the confirming button, the pattern for actions with no side effect.
- Rests on: docs/ux/accessibility-dashboard.md, Operable.

## 2026-11-21 · A retrying NextDNS API check reads "Retrying" and still counts as passing
- Decided by: Claude (default)
- Why: no alert has been raised inside the error window, so the menu's "checks OK" stays true, while the Health page stops showing "OK" beside an error.
- Rejected: counting it as failing, which would contradict the alerts; leaving "OK".
- Rests on: docs/ux/states-dashboard.md, Health; src/sentinel/health/monitor.py, `_api_check`.

## 2026-11-21 · In a narrow window the finding page draws its Decision panel twice, one hidden
- Decided by: Claude (default)
- Why: reordering with CSS would put the decision before the evidence on screen but after it in the tab order; two copies, one `display: none`, keep screen order and tab order the same with no JavaScript.
- Rejected: CSS `order` with `display: contents`; a sticky decision bar, which covers content in a short window.
- Rests on: docs/ux/adaptation-narrow-window.md.

## 2026-11-21 · Every findings list opens in triage order
- Decided by: Claude (default)
- Why: the Overview and J/K already used priority then time; the Findings page used time alone.
- Rejected: time order on Findings, which buries a critical finding under newer low ones.
- Rests on: docs/ux/navigation-findings-order.md.

## 2026-11-21 · The order decision has no site-map diagram
- Decided by: Claude (default)
- Why: the structure of the dashboard did not change, only a default order.
- Rejected: an HTML site map of unchanged pages.
- Rests on: docs/ux/navigation-findings-order.md.

## 2026-11-21 · The re-check after the fixes found one regression, fixed before release
- Decided by: Claude (default)
- Why: the plain rule names are longer than the ids, and the Rule column did not wrap, so the findings table ran past its panel at 1,440 pixels; the column now wraps between 150 and 180 pixels and the table fits at 1,280, 1,440 and 1,920.
- Rejected: shortening the names to fit one line.
- Rests on: docs/ux/evaluation-dashboard.md; src/sentinel/web/static/style.css, `.findings td.rule`.

## 2026-11-21 · Every evaluation finding was re-checked in the browser
- Decided by: Claude (default)
- Why: each change was seen working: counts in step within half a second of a decision, the dialog opening on Cancel, Retrying on Health, the Decision panel after the explanation at 1,000 pixels, the folded filters at 375, triage order, reason names on the real-data copy, and no column moving after a decision.
- Rejected: relying on the tests alone.
- Rests on: tests/integration/test_web_triage_polish.py.

## 2026-11-21 · Discord alerts and the digest lead with the rule's name
- Decided by: the designer
- Why: the dashboard titles findings by name; alerts and digests are where most findings are first read.
- Rejected: keeping the id as the lead in messages.
- Rests on: docs/ux/copy-dashboard.md, Alerts and the digest.
