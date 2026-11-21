# NextDNS Sentinel dashboard in a narrow window

## Platform-specific adaptation specs

The dashboard is reachable from the owner's PC only, so a narrow layout is a browser window docked beside other work: mouse and keyboard, glanced at between tasks, rather than a phone.

**One column, 1,180 pixels and narrower (a half-width window on a 1,920-pixel screen).** A finding's page stacks its two columns, so its Decision panel follows the evidence, the caches and the recent queries. The page draws the Decision panel twice: once in the side column, shown above 1,180 pixels, and once directly after the explanation, shown at 1,180 pixels and narrower. The hidden copy is `display: none`, so the page carries one Decision panel to assistive technology and one in the tab order at any width. Both copies post the same forms and work without JavaScript.

**Filters folded, 860 pixels and narrower.** The Findings filters sit inside a disclosure whose summary reads "Filters", followed by how many filters differ from their defaults ("2 set"; nothing when none). Without JavaScript the disclosure is open at every width. With JavaScript it starts closed at 860 pixels and narrower and open above, follows the window across that width, and stays open once the owner opens it. Above 860 pixels the summary is not shown and the filters look as they do now.

## Priority mapping per context

| Element | Wide window | Narrow window | Context fact |
|---|---|---|---|
| Decision on a finding's page | Side column, beside the explanation | Directly after the explanation, before the evidence | A glance between other tasks has time for the explanation and the decision, not the full record |
| Findings filters | Visible above the table | Folded behind "Filters", with the count of filters set | The first screen of a narrow window holds the filters or the first findings, not both |
| Facts and Revisions on a finding's page | Side column, under the decision | After the recent queries | Reference, read after deciding |
