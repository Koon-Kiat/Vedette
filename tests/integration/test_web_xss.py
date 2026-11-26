"""Hostile text in every place it can reach the dashboard must never execute.

Payloads go into device names and ids, blocklist reasons, domain names,
finding targets and evidence, the local model's output, health details and
digest text. Every page is then parsed and checked: the only scripts are our
own static files, no element has an event-handler attribute, no URL uses the
``javascript:`` scheme, every link stays inside the dashboard, and the payload
text shows up escaped.
"""

import re
from datetime import timedelta
from html.parser import HTMLParser
from typing import Any

import pytest

from tests.digest_fixture import PERIOD_END, PERIOD_START, build_fixture
from tests.integration.web_helpers import logged_in
from vedette.shared.models import AllowlistEntry, Analysis, Finding, OutgoingMessage, Severity
from vedette.sources.nextdns import parse_log_entry
from vedette.storage.analysis import AnalysisStore
from vedette.storage.health import HealthCheck, HealthStore
from vedette.storage.notifications import NotificationStore
from vedette.storage.store import Store
from vedette.storage.triage import TriageStore

PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "'><svg onload=alert(1)>",
    "</title><script>alert(2)</script>",
    '<a href="javascript:alert(3)">click</a>',
    '" autofocus onfocus=alert(4) x="',
    "{{7*7}}",
]
HOSTILE = " ".join(PAYLOADS)
URL_ATTRIBUTES = {"href", "src", "action", "formaction", "xlink:href", "hx-get", "hx-post"}
IN_PAGE = re.compile(r"#[A-Za-z][\w-]*")  # a jump within the page, such as the skip link
FORBIDDEN_TAGS = {"img", "iframe", "object", "embed", "frame", "base", "meta-refresh"}


class Audit(HTMLParser):
    """Collects every tag, attribute and script in a page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.problems: list[str] = []
        self.in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if tag in FORBIDDEN_TAGS:
            self.problems.append(f"<{tag}> element")
        if tag == "script":
            self.in_script = True
            if not values.get("src", "").startswith("/static/"):
                self.problems.append(f"script without our src: {values}")
        if tag == "svg" and "chart" not in values.get("class", "").split():
            self.problems.append("unexpected <svg>")
        for name, value in values.items():
            if name.startswith("on"):
                self.problems.append(f"event handler {name}= on <{tag}>")
            if name in URL_ATTRIBUTES:
                lowered = value.strip().lower()
                if lowered.startswith(("javascript:", "data:")):
                    self.problems.append(f"{name}={value!r}")
                inside = value.startswith("/") and not value.startswith("//")
                same_page = name == "href" and IN_PAGE.fullmatch(value) is not None
                if name in {"href", "action", "hx-get", "hx-post"} and not (inside or same_page):
                    self.problems.append(f"link leaves the dashboard: {name}={value!r}")

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self.in_script = False

    def handle_data(self, data: str) -> None:
        if self.in_script and data.strip():
            self.problems.append("inline script content")


def audit(html: str) -> list[str]:
    parser = Audit()
    parser.feed(html)
    parser.close()
    return parser.problems


async def plant(store: Store) -> None:
    """Put the payloads everywhere hostile text can come from."""
    await build_fixture(store)
    entries: list[dict[str, Any]] = [
        {
            "timestamp": (PERIOD_START + timedelta(hours=6, minutes=n)).isoformat(),
            "domain": f"x{n}.{payload}.evil.example",
            "root": f"{payload}.evil.example",
            "status": "blocked" if n % 2 else "default",
            "clientIp": payload,
            "device": {"id": f"dev-{payload}", "name": payload},
            "reasons": [{"id": f"blocklist:{payload}", "name": payload}],
        }
        for n, payload in enumerate(PAYLOADS)
    ]
    await store.save_events([parse_log_entry("def456", entry) for entry in entries])
    await store.commit_processed(
        [],
        [
            Finding(
                rule_id="young-domain",
                severity=Severity.HIGH,
                profile_id="def456",
                subject=f"dev-{payload}",
                device_mode=True,
                target=f"{payload}.evil.example",
                ts=PERIOD_START + timedelta(hours=6, minutes=n),
                dedupe_key=f"xss-{n}",
                evidence={payload: payload, "fqdn": f"x.{payload}", "device_name": payload},
                event_id=f"{n:064d}",
            )
            for n, payload in enumerate(PAYLOADS)
        ],
    )
    hostile = [f for f in await store.list_findings(limit=100) if ".evil.example" in f.target]
    await AnalysisStore(store.engine).save_analyses(
        [
            Analysis(
                finding_id=item.id,
                summary=HOSTILE[:400],
                likely_cause=HOSTILE[:300],
                recommended_action=HOSTILE[:300],
                priority=Severity.CRITICAL,
                group_key="x",
                confidence=0.5,
                source="llm",
                model=PAYLOADS[0],
            )
            for item in hostile
        ],
        now=PERIOD_END,
    )
    await TriageStore(store.engine).mark_benign(hostile[0].id, actor="cli", now=PERIOD_END)
    await HealthStore(store.engine).save(
        [HealthCheck("xss", HOSTILE[:128], False, HOSTILE[:300])], now=PERIOD_END
    )
    await NotificationStore(store.engine).record_digest(
        period_start=PERIOD_START,
        period_end=PERIOD_END,
        now=PERIOD_END,
        message=OutgoingMessage(title=HOSTILE[:300], body=HOSTILE, priority=Severity.MEDIUM),
        data={},
    )


@pytest.fixture
async def planted(store: Store) -> Store:
    await plant(store)
    return store


async def pages(store: Store) -> list[str]:
    finding_ids = [f.id for f in await store.list_findings(limit=100)]
    (digest,) = await NotificationStore(store.engine).digests(limit=1)
    hostile_from = int((PERIOD_START + timedelta(hours=6)).timestamp())
    hostile_to = int((PERIOD_START + timedelta(hours=7)).timestamp())
    return [
        "/",
        "/findings?status=all",
        "/findings?status=all&device=dev-%3Cscript%3Ealert(1)%3C/script%3E",
        *(f"/findings/{fid}" for fid in finding_ids),
        "/domains?period=7d",
        "/devices",
        "/allowlist",
        "/digests",
        f"/digests/{digest.id}",
        "/health",
        "/evaluation",
        "/live",
        "/partials/decide",
        f"/partials/window?from={hostile_from}&to={hostile_to}",
    ]


async def test_no_page_lets_hostile_text_execute(planted: Store) -> None:
    configured = [AllowlistEntry(root=f"{PAYLOADS[0]}.evil.example", device=PAYLOADS[1])]
    async with logged_in(planted, allowlist=configured) as (client, _):
        for path in await pages(planted):
            response = await client.get(path)
            assert response.status_code == 200, path
            assert response.headers["content-type"].startswith("text/html")
            assert audit(response.text) == [], path


async def test_hostile_text_is_shown_escaped_not_dropped(planted: Store) -> None:
    async with logged_in(planted) as (client, _):
        detail_ids = [
            f.id for f in await planted.list_findings(limit=100) if ".evil.example" in f.target
        ]
        page = await client.get(f"/findings/{detail_ids[0]}")

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert "{{7*7}}" in page.text
    assert "<script>alert" not in page.text


async def test_the_row_returned_after_an_action_is_safe_too(planted: Store) -> None:
    fid = next(f.id for f in await planted.list_findings(limit=100) if ".evil.example" in f.target)
    async with logged_in(planted) as (client, csrf):
        response = await client.post(
            f"/findings/{fid}/acknowledge",
            data={"csrf_token": csrf},
            headers={"HX-Request": "true"},
        )

    assert response.status_code == 200
    assert audit(response.text) == []


@pytest.mark.parametrize(
    "bad",
    [
        "<script>alert(1)</script>",
        '<script src="https://cdn.example/x.js"></script>',
        '<img src="x" onerror="alert(1)">',
        '<a href="javascript:alert(1)">x</a>',
        '<a href="https://evil.example/">x</a>',
        '<a href="#x:alert(1)">x</a>',
        '<form action="//evil.example/"></form>',
        '<svg onload="alert(1)"></svg>',
        '<svg class="charted"></svg>',
        '<div onclick="x()"></div>',
    ],
)
def test_the_checker_itself_catches_unsafe_html(bad: str) -> None:
    assert audit(bad) != []


def test_the_checker_accepts_our_own_markup() -> None:
    good = (
        '<script src="/static/vendor/htmx-2.0.11.min.js" defer></script>'
        '<a href="#main">skip</a><a href="/findings/3">x</a>'
        '<form method="post" action="/logout"></form>'
        '<svg class="chart"><rect class="bar-allowed"/></svg>'
        '<svg class="chart span-bar"><rect class="span-seen"/></svg>'
    )
    assert audit(good) == []
