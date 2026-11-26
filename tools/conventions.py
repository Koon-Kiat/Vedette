"""Checks commit messages and pull requests against the project's writing rules.

``.githooks/commit-msg`` runs it on every commit, and the conventions workflow on
every pull request and every push to main. Each problem it reports says what to
write instead.

    python tools/conventions.py commit-msg FILE        (FILE may be -)
    git log --format=%x1e%h%n%B BASE..HEAD | python tools/conventions.py commits -
    python tools/conventions.py pr --number N --title TITLE [--body-file FILE]
"""

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

TYPES = (
    "build",
    "chore",
    "ci",
    "docs",
    "feat",
    "fix",
    "perf",
    "refactor",
    "revert",
    "style",
    "test",
)
CONVENTIONAL = re.compile(rf"^(?:{'|'.join(TYPES)})(?:\([a-z0-9][a-z0-9-]*\))?!?: \S")
GIT_SUBJECTS = ("Merge ", 'Revert "', "fixup! ", "squash! ", "amend! ")
SUBJECT_LIMIT = 72
BODY_WIDTH = 72

_ASSISTANTS = r"(?:claude|anthropic|chatgpt|openai|copilot|gemini|codex)"
AI_ATTRIBUTION = re.compile(
    rf"co-authored-by:[^\n]*{_ASSISTANTS}"
    rf"|generated (?:with|by)[^\n]*{_ASSISTANTS}"
    r"|claude\.ai/code|claude\.com/claude-code|\U0001f916",
    re.IGNORECASE,
)
MILESTONE_CODE = re.compile(r"\bM[0-7]\b")
BACKLOG_ID = re.compile(r"\b(?:EV|DR|TI|AN|UX)-\d+\b")

SECTIONS = ("Summary", "Changes", "Testing")
OPTIONAL_SECTION = "Notes"
_HEADING = re.compile(r"^(#{1,2})[ \t]+(.+?)[ \t#]*$", re.MULTILINE)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_SCISSORS = "# ------------------------ >8 ------------------------"


def _text_problems(where: str, text: str) -> list[str]:
    problems = [
        f"{where}: remove {match.group(0)!r}; commits and pull requests carry no AI or "
        "assistant attribution."
        for match in AI_ATTRIBUTION.finditer(text)
    ]
    problems += [
        f"{where}: {code!r} is a milestone code; name the work instead "
        "(scaffold, collector, enrichment and rules, dashboard, ...)."
        for code in dict.fromkeys(MILESTONE_CODE.findall(text))
    ]
    return problems


def _conventional_problem(where: str) -> str:
    return (
        f"{where}: write a Conventional Commit, such as 'fix(enrich): keep the root'; "
        f"the type is one of {', '.join(TYPES)}."
    )


def _title_problems(title: str, number: int) -> list[str]:
    problems = [] if CONVENTIONAL.match(title) else [_conventional_problem("title")]
    suffix = f" (#{number})"
    limit = SUBJECT_LIMIT - len(suffix)
    if len(title) > limit:
        problems.append(
            f"title: {len(title)} characters; shorten it to {limit} so the squashed "
            f"commit's subject, with {suffix.strip()!r} added, fits in {SUBJECT_LIMIT}."
        )
    return problems


def _backlog_problems(where: str, text: str) -> list[str]:
    return [
        f"{where}: {found!r} is an internal backlog id; describe the change itself."
        for found in dict.fromkeys(BACKLOG_ID.findall(text))
    ]


def message_text(raw: str) -> str:
    """The commit message git will record: comment lines and the verbose diff removed."""
    kept = []
    for line in raw.splitlines():
        if line == _SCISSORS:
            break
        if not line.startswith("#"):
            kept.append(line)
    return "\n".join(kept).strip()


def _body_problems(where: str, text: str) -> list[str]:
    lines = text.splitlines()
    if len(lines) > 1 and lines[1].strip():
        return [f"{where}: leave a blank line between the subject and the body."]
    long = [
        (number, len(line))
        for number, line in enumerate(lines, 1)
        if number > 1 and len(line) > BODY_WIDTH and " " in line.strip()
    ]
    if not long:
        return []
    number, length = long[0]
    more = f" and {len(long) - 1} more" if len(long) > 1 else ""
    return [
        f"{where}: body line {number} is {length} characters{more}; wrap the body at "
        f"{BODY_WIDTH}, as git log, email patches and review tools show it as written. "
        "Only a single word, such as a URL, may run over."
    ]


def check_commit(raw: str, *, where: str = "commit message") -> list[str]:
    """Problems with one commit message, as written in the editor or by ``-m``."""
    text = message_text(raw)
    if not text:
        return []
    subject = text.splitlines()[0]
    problems = []
    if not subject.startswith(GIT_SUBJECTS) and not CONVENTIONAL.match(subject):
        problems.append(_conventional_problem(f"{where} subject"))
    return problems + _body_problems(where, text) + _text_problems(where, text)


def _section_problems(body: str) -> list[str]:
    headings = [(len(marks), title) for marks, title in _HEADING.findall(body)]
    found = [title for _, title in headings]
    allowed = (list(SECTIONS), [*SECTIONS, OPTIONAL_SECTION])
    if found in allowed and all(level == 2 for level, _ in headings):
        return []
    listed = ", ".join(found) or "none"
    return [
        f"description: use the template's sections, '## Summary', '## Changes' and "
        f"'## Testing', then '## Notes' if needed (found: {listed}). Fixes made during "
        "review go under Changes, beside the change they belong to."
    ]


def check_pull_request(title: str, body: str | None, *, number: int) -> list[str]:
    """Problems with a pull request; ``body`` is ``None`` when only the title is checked.

    The title becomes the squashed commit's subject, which GitHub ends with
    `` (#number)``, so the limit depends on the pull request's number.
    """
    problems = _title_problems(title, number)
    problems += _backlog_problems("title", title) + _text_problems("title", title)
    if body is not None:
        text = _HTML_COMMENT.sub("", body)
        problems += _section_problems(text)
        problems += _backlog_problems("description", text)
        problems += _text_problems("description", text)
    return problems


def check_log(log: str) -> list[str]:
    """Problems with every commit in ``git log --format=%x1e%h%n%B`` output."""
    problems = []
    for record in log.split("\x1e")[1:]:
        short, _, message = record.partition("\n")
        problems += check_commit(message, where=f"commit {short}")
    return problems


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """Run one check and print its problems; the exit status is 1 if there are any."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("commit-msg").add_argument("file")
    commands.add_parser("commits").add_argument("file")
    pull_request = commands.add_parser("pr")
    pull_request.add_argument("--number", type=int, required=True)
    pull_request.add_argument("--title", required=True)
    pull_request.add_argument("--body-file")
    args = parser.parse_args(argv)

    if args.command == "commit-msg":
        problems = check_commit(_read(args.file))
    elif args.command == "commits":
        problems = check_log(_read(args.file))
    else:
        body = None if args.body_file is None else _read(args.body_file)
        problems = check_pull_request(args.title, body, number=args.number)
    sys.stderr.writelines(f"{problem}\n" for problem in problems)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
