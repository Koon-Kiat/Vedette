<!--
Title: a Conventional Commit, the same as the squashed commit will be,
for example "feat(eval): measure false alerts on names the rules do not skip".

Write for someone who has not read the code. Keep every heading; write
"None" under one that does not apply, so a reader knows it was considered.
Leave out internal tracking ids such as backlog item numbers.
-->

## Why

<!-- The problem or gap this fixes, in plain words. -->

## What changes

<!-- What someone running Vedette will notice first, then the main code changes, one bullet each.
     Fixes made during review belong here too, grouped with the change they affect, not in a section of their own. -->

## What leaves your machine

<!-- Any new download, lookup or message sent off the machine, and how to switch it off. "Nothing new" if none. -->

## Testing

<!-- Tick what ran, in the dev container (docker compose --profile dev run --rm dev ...), with the result. -->

- [ ] `ruff check .`
- [ ] `ruff format --check .`
- [ ] `mypy`
- [ ] `pytest`: passed / skipped
- [ ] Anything else that ran, such as `vedette eval` or the dashboard in a browser:

<!-- Say what was not tested, and why. -->

## After merging

<!-- Migrations, config changes, rebuilds or restarts the owner has to do. "Nothing" if none. -->

## Follow-ups

<!-- Known issues left for later, one line each. "None" if none. -->
