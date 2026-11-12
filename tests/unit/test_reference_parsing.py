import io
import zipfile

import pytest

from sentinel.enrich.popularity import parse_tranco
from sentinel.enrich.threat_intel import candidates, parse_feed


def tranco_zip(text: str, name: str = "top-1m.csv") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, text)
    return buffer.getvalue()


def test_tranco_rows_are_parsed_as_domain_and_rank() -> None:
    rows = list(parse_tranco(tranco_zip("1,google.com\r\n2,Cloudflare.com\r\n3,example.org\r\n")))

    assert rows == [("google.com", 1), ("cloudflare.com", 2), ("example.org", 3)]


def test_tranco_bad_rows_are_skipped() -> None:
    rows = [
        "1,good.example",
        "not-a-row",
        "x,bad-rank.example",
        "4,",
        "5,ok.example",
        "-1,neg.example",
    ]
    text = "\r\n".join(rows) + "\r\n"

    assert list(parse_tranco(tranco_zip(text))) == [("good.example", 1), ("ok.example", 5)]


def test_tranco_duplicate_domains_keep_their_best_rank() -> None:
    rows = list(parse_tranco(tranco_zip("1,a.example\r\n2,b.example\r\n3,a.example\r\n")))

    assert rows == [("a.example", 1), ("b.example", 2)]


def test_tranco_row_limit_is_enforced() -> None:
    text = "".join(f"{n},site{n}.example\r\n" for n in range(1, 51))

    assert len(list(parse_tranco(tranco_zip(text), max_rows=10))) == 10


def test_tranco_rejects_something_that_is_not_a_zip() -> None:
    with pytest.raises(ValueError, match="zip"):
        list(parse_tranco(b"<html>not a zip</html>"))


def test_tranco_rejects_an_archive_that_expands_too_much() -> None:
    with pytest.raises(ValueError, match="too large"):
        list(parse_tranco(tranco_zip("1,a.example\r\n" * 1000), max_uncompressed_bytes=100))


def test_domain_feed_ignores_comments_blank_lines_and_junk() -> None:
    text = "# Title: sample\n\nBad.Example\n  spaced.example  \nnot a domain\nhttp://x/\n-bad-.example.\n"

    assert list(parse_feed(text, "domains")) == ["bad.example", "spaced.example"]


def test_hosts_feed_takes_the_name_after_the_address() -> None:
    text = "# hosts\n127.0.0.1 localhost\n0.0.0.0 bad.example\n127.0.0.1\tworse.example # note\n"

    assert list(parse_feed(text, "hosts")) == ["bad.example", "worse.example"]


def test_url_feed_takes_the_host_name_only() -> None:
    text = "http://bad.example/login\nhttps://WWW.worse.example:8443/a?b=c\nhttp://198.51.100.9/x\njunk\n"

    assert list(parse_feed(text, "urls")) == ["bad.example", "www.worse.example"]


def test_candidates_are_the_name_and_each_parent_down_to_the_root() -> None:
    assert candidates("a.b.bad.example", "bad.example") == [
        "a.b.bad.example",
        "b.bad.example",
        "bad.example",
    ]


def test_candidates_never_include_a_bare_suffix() -> None:
    assert candidates("a.bad.example", None) == ["a.bad.example", "bad.example"]
    assert candidates("example", None) == ["example"]
    assert candidates("www.site.co.uk", "site.co.uk") == ["www.site.co.uk", "site.co.uk"]
