"""Static checks on the dashboard's templates and vendored files."""

import hashlib
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from vedette.web import app as web_app

WEB = Path(web_app.__file__).resolve().parent
TEMPLATES = sorted((WEB / "templates").glob("*.html"))
HTMX = WEB / "static" / "vendor" / "htmx-2.0.11.min.js"


class Scripts(HTMLParser):
    """Every <script> tag in a template: its attributes and any text inside it."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[dict[str, str | None]] = []
        self.inline: list[str] = []
        self._inside = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":  # the parser lowercases tag names
            self.tags.append(dict(attrs))
            self._inside = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._inside = False

    def handle_data(self, data: str) -> None:
        if self._inside:
            self.inline.append(data)


def test_there_are_templates_to_check() -> None:
    assert len(TEMPLATES) >= 8


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_templates_never_turn_escaping_off(template: Path) -> None:
    text = template.read_text(encoding="utf-8")

    assert "|safe" not in text.replace(" ", "")
    assert "autoescape false" not in text
    assert "Markup(" not in text


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_templates_contain_no_inline_script_or_style(template: Path) -> None:
    text = template.read_text(encoding="utf-8")
    scripts = Scripts()
    scripts.feed(text)
    scripts.close()

    assert "".join(scripts.inline).strip() == "", "inline script content"
    for attrs in scripts.tags:
        assert (attrs.get("src") or "").startswith("/static/")
    # Every script tag, in any case, is one the parser saw.
    assert text.lower().count("<script") == len(scripts.tags)
    assert "<style" not in text.lower()
    assert not re.search(r"\sstyle\s*=", text, flags=re.I)
    assert not re.search(r"\son[a-z]+\s*=", text, flags=re.I)
    assert "javascript:" not in text.lower()
    assert "hx-on" not in text


def test_the_template_environment_escapes_everything() -> None:
    assert web_app.TEMPLATE_ENV.autoescape is True


def test_the_vendored_htmx_is_the_reviewed_file() -> None:
    digest = hashlib.sha256(HTMX.read_bytes()).hexdigest()

    assert digest == web_app.HTMX_SHA256


FONTS = {
    "mona-sans-latin-standard-normal.woff2": (
        "5ea3740633e5ac7af56c13d7e8ec32bcae12e7723e53d34284469a8947ccb2f3"
    ),
    "jetbrains-mono-latin-wght-normal.woff2": (
        "18be452724bfdc236c074ca94a249a7f41a86752c7d04ab258ce9ed5651f6a7e"
    ),
    "jetbrains-mono-latin-wght-italic.woff2": (
        "a8afa085e9ca5e53434e2ee918ba6b65c7dd4dda56509976b36591478c99d62e"
    ),
}


@pytest.mark.parametrize(("name", "sha256"), FONTS.items())
def test_the_vendored_fonts_are_the_reviewed_files(name: str, sha256: str) -> None:
    font = WEB / "static" / "fonts" / name

    assert hashlib.sha256(font.read_bytes()).hexdigest() == sha256
    assert (WEB / "static" / "fonts" / f"{name.split('-latin')[0]}-LICENSE.txt").is_file()


UPLOT = {
    "uPlot-1.6.32.iife.min.js": "19c8d4c6ad88929a79f4ae49d6f7161566dfd0ba3d15cc495e974f787eb78f1f",
    "uPlot-1.6.32.min.css": "df630c6a8d6f8eeaff264b50f73ce5b114f646ffd9a0bb74f049b0a00135fa04",
    "uPlot-LICENSE.txt": "8f989229699b4fe2f1a0432d0e9edc338a8a911e250e2d1b01ecd770a5f5b1bd",
}


@pytest.mark.parametrize(("name", "sha256"), UPLOT.items())
def test_the_vendored_uplot_is_the_reviewed_file(name: str, sha256: str) -> None:
    file = WEB / "static" / "vendor" / name

    assert hashlib.sha256(file.read_bytes()).hexdigest() == sha256


@pytest.mark.parametrize("name", ["live.js", "charts.js", "ui.js"])
def test_our_scripts_never_write_html(name: str) -> None:
    script = (WEB / "static" / name).read_text(encoding="utf-8")

    for forbidden in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "DOMParser",
        "createContextualFragment",
        "document.write",
        "eval(",
        "new Function",
        'setAttribute("style"',
        "cssText",
    ):
        assert forbidden not in script, forbidden
    assert "textContent" in script


def test_the_chart_script_builds_urls_only_from_numbers() -> None:
    script = (WEB / "static" / "charts.js").read_text(encoding="utf-8")

    # The only requests and navigations, each with numbers the script checked.
    assert script.count("fetch(") == 1
    assert "fetch(`/api/series?from=${from}&to=${to}&points=${points}`" in script
    assert "return Math.round(clamp(width / 6, 60, 480));" in script
    assert "`/partials/window?from=${Math.floor(from)}&to=${Math.ceil(to)}`" in script
    assert "window.location.assign(`/findings/${c.items[0].id}`)" in script
    assert "Number.isInteger(c.items[0].id)" in script


def test_the_script_check_sees_any_case_and_spacing() -> None:
    scripts = Scripts()
    scripts.feed('<SCRIPT type="x">alert(1)</script >')
    scripts.close()

    assert scripts.tags == [{"type": "x"}]
    assert scripts.inline == ["alert(1)"]
