import json
import logging
from typing import Any

import pytest
import structlog

from sentinel.log import REDACTED, configure_logging, make_redactor

SECRET = "not-a-real-secret-value"  # noqa: S105 - fake value used only by these tests


def redact(event: dict[str, Any], secrets: tuple[str, ...] = ()) -> dict[str, Any]:
    result = make_redactor(secrets)(None, "info", event)
    assert isinstance(result, dict)
    return result


@pytest.mark.parametrize(
    "key",
    [
        "api_key",
        "X-Api-Key",
        "nextdns_api_key",
        "Authorization",
        "password",
        "token",
        "notify_token",
        "client_secret",
        "cookie",
        "Set-Cookie",
    ],
)
def test_values_under_sensitive_keys_are_redacted(key: str) -> None:
    assert redact({"event": "x", key: "hunter2"})[key] == REDACTED


def test_sensitive_keys_are_redacted_inside_nested_structures() -> None:
    out = redact({"event": "x", "request": {"meta": [{"api_key": "hunter2", "ok": 1}]}})

    assert out["request"] == {"meta": [{"api_key": REDACTED, "ok": 1}]}


def test_whole_header_mappings_are_redacted() -> None:
    out = redact({"event": "x", "headers": {"Accept": "application/json", "X-Api-Key": "v"}})

    assert out["headers"] == REDACTED


def test_known_secret_values_are_scrubbed_from_any_string() -> None:
    out = redact(
        {"event": f"calling with {SECRET}", "url": f"https://x.test/?k={SECRET}", "n": [SECRET]},
        secrets=(SECRET,),
    )

    assert out["event"] == f"calling with {REDACTED}"
    assert out["url"] == f"https://x.test/?k={REDACTED}"
    assert out["n"] == [REDACTED]


def test_blank_secrets_do_not_corrupt_output() -> None:
    assert redact({"event": "hello"}, secrets=("", "  "))["event"] == "hello"


def test_ordinary_fields_are_left_alone() -> None:
    event = {"event": "stored", "domain": "example.com", "count": 3, "tokens_used": 12}

    assert redact(event) == event


def test_structlog_output_is_one_redacted_json_object_per_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO", secrets=(SECRET,))

    structlog.get_logger("sentinel.test").info("fetched", url=f"https://x.test/{SECRET}", pages=2)

    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "fetched"
    assert record["level"] == "info"
    assert record["logger"] == "sentinel.test"
    assert record["pages"] == 2
    assert record["url"] == f"https://x.test/{REDACTED}"
    assert record["timestamp"].endswith("Z")
    assert SECRET not in lines[0]


def test_stdlib_logging_from_libraries_is_also_json_and_redacted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO", secrets=(SECRET,))

    logging.getLogger("some.library").warning("retrying with key %s", SECRET)

    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == f"retrying with key {REDACTED}"
    assert record["level"] == "warning"
    assert record["logger"] == "some.library"


def test_messages_below_the_configured_level_are_dropped(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("WARNING")

    structlog.get_logger("sentinel.test").info("quiet")
    structlog.get_logger("sentinel.test").warning("loud")

    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line)["event"] for line in lines] == ["loud"]


def test_exceptions_are_rendered_and_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", secrets=(SECRET,))

    try:
        raise RuntimeError(f"bad key {SECRET}")
    except RuntimeError:
        structlog.get_logger("sentinel.test").exception("failed")

    out = capsys.readouterr().out
    record = json.loads(out.strip())
    assert "RuntimeError" in record["exception"]
    assert SECRET not in out


def test_http_client_request_logs_are_silenced_below_warning(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("DEBUG")

    logging.getLogger("httpx").info("HTTP Request: GET https://x.test/profiles/abc123/logs")
    logging.getLogger("httpcore.connection").debug("connect_tcp.started")
    logging.getLogger("httpx").warning("something worth seeing")

    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line)["event"] for line in lines] == ["something worth seeing"]
