"""Helpers for tests that serve a downloadable ``rank,name`` list."""

import io
import zipfile

#: Where tests serve the popular-hostname list (never a real address).
HOSTNAMES_URL = "https://lists.test/top-1m.csv.zip"


def zipped(rows: list[str], member: str = "top-1m.csv") -> bytes:
    """A zip archive holding one CSV member with the given lines."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(member, "\n".join(rows) + "\n")
    return buffer.getvalue()
