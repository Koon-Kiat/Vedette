import pytest

from sentinel.notify.defang import clean_text, defang


def test_dots_in_a_domain_are_bracketed() -> None:
    assert defang("example.com") == "example[.]com"


def test_every_dot_is_bracketed() -> None:
    assert defang("a.b.example.co.uk") == "a[.]b[.]example[.]co[.]uk"


def test_url_schemes_are_neutralised() -> None:
    assert defang("http://evil.example/path") == "hxxp://evil[.]example/path"
    assert defang("HTTPS://evil.example") == "hxxps://evil[.]example"


def test_defanging_twice_changes_nothing() -> None:
    once = defang("http://evil.example")

    assert defang(once) == once


def test_ip_addresses_are_defanged_too() -> None:
    assert defang("198.51.100.7") == "198[.]51[.]100[.]7"


@pytest.mark.parametrize(
    "hostile", ["\x1b[31mred\x1b[0m.example", "a\r\nb.example", "a\x00b.example"]
)
def test_control_characters_are_removed(hostile: str) -> None:
    result = defang(hostile)

    assert all(ch.isprintable() for ch in result)
    assert "\x1b" not in result


def test_result_contains_nothing_a_client_would_auto_link() -> None:
    result = defang("https://www.evil.example/login")

    assert "http" not in result.lower()
    assert "." not in result.replace("[.]", "")


def test_clean_text_removes_control_characters_and_caps_length() -> None:
    assert clean_text("Living\x1b[2J Room\nTV", limit=100) == "Living[2J Room TV"
    assert clean_text("x" * 500, limit=20) == "x" * 20


def test_clean_text_collapses_whitespace() -> None:
    assert clean_text("a \t\n  b", limit=100) == "a b"


def test_prose_keeps_its_sentence_punctuation() -> None:
    from sentinel.notify.defang import defang_text

    text = (
        "A device reached evil.example twice. See https://evil.example/a now. Version 1.2 is old."
    )

    assert defang_text(text) == (
        "A device reached evil[.]example twice. See hxxps://evil[.]example/a now. "
        "Version 1[.]2 is old."
    )


def test_defanging_prose_twice_changes_nothing() -> None:
    from sentinel.notify.defang import defang_text

    once = defang_text("Reached a.b.example. Done.")

    assert defang_text(once) == once
    assert once == "Reached a[.]b[.]example. Done."


def test_prose_defanging_leaves_no_clickable_name() -> None:
    from sentinel.notify.defang import defang_text

    result = defang_text("go to www.evil.example/login, or evil.example:8443.")

    assert "evil.example" not in result
    assert "www.evil" not in result
