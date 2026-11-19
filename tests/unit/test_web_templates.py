"""Static checks on the dashboard's templates and vendored files."""

import hashlib
import re
from pathlib import Path

import pytest

from sentinel.web import app as web_app

WEB = Path(web_app.__file__).resolve().parent
TEMPLATES = sorted((WEB / "templates").glob("*.html"))
HTMX = WEB / "static" / "vendor" / "htmx-2.0.11.min.js"


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

    for script in re.findall(r"<script\b[^>]*>(.*?)</script>", text, flags=re.S):
        assert script.strip() == "", "inline script content"
    for tag in re.findall(r"<script\b[^>]*>", text):
        assert 'src="/static/' in tag
    assert "<style" not in text
    assert not re.search(r"\sstyle\s*=", text)
    assert not re.search(r"\son[a-z]+\s*=", text)
    assert "javascript:" not in text.lower()
    assert "hx-on" not in text


def test_the_template_environment_escapes_everything() -> None:
    assert web_app.TEMPLATE_ENV.autoescape is True


def test_the_vendored_htmx_is_the_reviewed_file() -> None:
    digest = hashlib.sha256(HTMX.read_bytes()).hexdigest()

    assert digest == web_app.HTMX_SHA256
