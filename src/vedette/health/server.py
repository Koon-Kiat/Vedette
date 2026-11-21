"""A minimal ``/healthz`` HTTP endpoint, bound to the loopback interface.

It answers ``GET /healthz`` and nothing else, reads at most one short request
line and a few headers with a timeout, and closes every connection after one
response. Inside the container it is reachable only by the container itself,
which is what Docker's health check uses.
"""

import asyncio
import json
from collections.abc import Callable
from http import HTTPStatus
from typing import Any

import structlog

log = structlog.get_logger(__name__)

MAX_LINE = 1024
MAX_HEADERS = 50
READ_TIMEOUT = 5.0

type Snapshot = Callable[[], tuple[int, dict[str, Any]]]


def _response(status: int, body: dict[str, Any] | None = None) -> bytes:
    payload = json.dumps(body if body is not None else {"error": HTTPStatus(status).phrase})
    data = payload.encode("utf-8")
    head = (
        f"HTTP/1.1 {status} {HTTPStatus(status).phrase}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(data)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n"
    )
    return head.encode("ascii") + data


async def _answer(reader: asyncio.StreamReader, snapshot: Snapshot) -> bytes:
    try:
        async with asyncio.timeout(READ_TIMEOUT):
            line = await reader.readline()
            for _ in range(MAX_HEADERS):
                header = await reader.readline()
                if header in (b"\r\n", b"\n", b""):
                    break
    except TimeoutError, ValueError, ConnectionError:
        return _response(400)
    if len(line) > MAX_LINE:
        return _response(400)
    parts = line.decode("latin-1").split()
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return _response(400)
    method, path = parts[0], parts[1]
    if path != "/healthz":
        return _response(404)
    if method != "GET":
        return _response(405)
    status, body = snapshot()
    return _response(status, body)


async def start_health_server(snapshot: Snapshot, *, host: str, port: int) -> asyncio.Server:
    """Start serving ``/healthz`` from ``snapshot`` on ``host``:``port``."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            writer.write(await _answer(reader, snapshot))
            await writer.drain()
        except ConnectionError:
            pass
        except Exception:  # one bad request must not stop the endpoint; logged
            log.exception("healthz_unexpected_error")
        finally:
            writer.close()

    server = await asyncio.start_server(handle, host=host, port=port, limit=MAX_LINE * 8)
    log.info("healthz_listening", host=host, port=server.sockets[0].getsockname()[1])
    return server
