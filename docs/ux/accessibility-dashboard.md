# NextDNS Sentinel dashboard: the Mark benign confirmation and outside names

## Accessibility Audit — Per WCAG Principle

### Perceivable

**Low.** Outside names in "Evidence when it fired" are set in the body face, so the mark that tells the owner a name came from DNS traffic disappears where the decision is made. Meets WCAG; falls short of the dashboard's rule that every outside name carries the same mark.
- **Change:** Every evidence value that came from outside (`fqdn`, `sample_fqdn`, `root`, `label`, `threat_match`, `device_name`, `category`, `category_name`) is wrapped in the `name` style: JetBrains Mono italic at 0.93em. The confirmation dialog sets its `{domain}` the same way.
- **Test:** On a young-domain finding, the Name queried and Domain values compute `font-style: italic` and the mono family; numeric rows (Domain age, Top-sites rank) do not.

- **Keep:** defanged names (`example[.]com`) read aloud with their brackets, so a screen-reader user also hears that the name was defanged.

### Operable

**Medium.** The Mark benign dialog opens with focus on its confirming button, so Enter pressed twice from the row allowlists the domain on that profile. Fails the intent of 3.3.4 Error Prevention for an action that silences future alerts.
- **Change:** Focus lands on Cancel when the dialog opens. Confirming takes Tab then Enter, or a click.
- **Test:** Focus Mark benign on a young-domain row and press Enter twice: the dialog is still open and the row unchanged.

- **Keep:** Escape and Cancel close the dialog and return focus to the row's Mark benign button.
- **Keep:** the dialog is modal (`showModal`), so Tab stays inside it.

### Robust

**Medium.** The dialog is named by its title but its body is not tied to it, so a screen reader announces "Please confirm, dialog" and nothing about the domain or the profile. Fails 4.1.2 Name, Role, Value in spirit: the consequence is not exposed when focus enters.
- **Change:** The dialog carries `aria-describedby` pointing at its body paragraph, and its title states the action (strings in docs/ux/copy-dashboard.md, Mark benign confirmation).
- **Test:** The dialog's accessible description equals its body text, including the defanged domain and the profile label.

## Screen Reader Flow Documentation

| Change | Announced | Politeness |
|---|---|---|
| Mark benign dialog opens | Its title, then its body (title as name, body as description) | Native dialog focus announcement |

## Keyboard Navigation Map

| Event | Focus lands on | Focus returns to |
|---|---|---|
| Mark benign dialog opens | Cancel | — |
| Dialog closes with Cancel or Escape | — | The row's Mark benign button |
| Dialog closes with Mark benign | — | The replaced row's first action, as for any decision |
