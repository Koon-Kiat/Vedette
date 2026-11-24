"""Helpers for tests that serve a downloadable ``rank,name`` list."""

import io
import zipfile

#: Where tests serve the popular-hostname list (never a real address).
HOSTNAMES_URL = "https://lists.test/top-1m.csv.zip"


def zipped(
    rows: list[str], member: str = "top-1m.csv", compression: int = zipfile.ZIP_STORED
) -> bytes:
    """A zip archive holding one CSV member with the given lines."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        archive.writestr(member, "\n".join(rows) + "\n")
    return buffer.getvalue()


def damaged(compression: int, member: str = "top-1m.csv") -> bytes:
    """A zip whose member's data is corrupted after the local header (bad CRC or stream)."""
    data = bytearray(zipped([f"{n},site{n}.example" for n in range(1, 400)], member, compression))
    start = 30 + len(member)  # the fixed local header, then the name, then the data
    for offset in range(start + 5, start + 40):
        data[offset] ^= 0xFF
    return bytes(data)
