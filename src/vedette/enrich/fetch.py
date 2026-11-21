"""Size-limited downloads of reference data, and the domain-name check they share."""

import re

import httpx

_LABEL = r"[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")


class ReferenceFetchError(Exception):
    """A reference-data download failed or was not usable."""


def is_domain(name: str) -> bool:
    """Whether ``name`` is a plain multi-label domain name (not an IP address)."""
    return len(name) <= 253 and bool(_DOMAIN.match(name)) and not name.rsplit(".", 1)[-1].isdigit()


async def fetch_limited(client: httpx.AsyncClient, url: str, *, max_bytes: int) -> bytes:
    """Download ``url``, refusing anything larger than ``max_bytes``.

    Raises:
        ReferenceFetchError: Network failure, a status other than 200, or a
            body over the size limit.
    """
    try:
        async with client.stream("GET", url) as response:
            if response.status_code != 200:
                raise ReferenceFetchError(f"HTTP {response.status_code}")
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    raise ReferenceFetchError(f"larger than {max_bytes} bytes")
                chunks.append(chunk)
    except httpx.HTTPError as exc:
        raise ReferenceFetchError(type(exc).__name__) from exc
    return b"".join(chunks)
