"""Reads a NextDNS log export: the CSV downloaded from the dashboard's Logs page.

Checked against a real export and the API on 2026-11-12:

* the file is the **raw** view. It has one row per query, including every
  query type and every repeat, where the API's default view keeps only A, AAAA
  and HTTPS lookups and removes repeats;
* every entry of the API's default view for the same period is present in the
  file, and a row here gets the same event id as its API twin, so loading a
  file never double-counts events the collector already stored;
* in raw mode the file and the API match row for row.

In default mode the reader therefore keeps navigational query types and merges
rows that differ only by query type. NextDNS's own removal of repeats is not
documented and is not imitated, so a file still yields more events than the
API would for the same period.
"""

import csv
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.sources.base import DnsEvent
from sentinel.sources.nextdns import parse_log_entry

REQUIRED_COLUMNS = ("timestamp", "domain")
NAVIGATIONAL_TYPES = frozenset({"A", "AAAA", "HTTPS"})
_MAX_FIELD_BYTES = 1_000_000


class ExportFormatError(Exception):
    """The file is not a NextDNS log export this reader understands."""


@dataclass(slots=True)
class ExportResult:
    """What a log export contained.

    Attributes:
        events: The usable events, in file order, each id once.
        rows: Data rows in the file.
        skipped_malformed: Rows without a usable timestamp or domain.
        skipped_other_types: Rows left out in default mode for having a query
            type the API's default view does not include.
        merged_same_instant: Rows merged into another because, in default
            mode, they differed only by query type.
    """

    events: list[DnsEvent] = field(default_factory=list)
    rows: int = 0
    skipped_malformed: int = 0
    skipped_other_types: int = 0
    merged_same_instant: int = 0


def read_export(path: Path, profile_id: str, *, raw: bool) -> ExportResult:
    """Read a NextDNS log export into events for ``profile_id``.

    Args:
        path: The CSV file.
        profile_id: Profile the file was exported from.
        raw: Whether the profile is collected in raw mode. Must match
            ``ingest.raw``, so that file and API events get matching ids.

    Raises:
        ExportFormatError: The file has no header or lacks a required column.
        OSError: The file cannot be read.
    """
    csv.field_size_limit(_MAX_FIELD_BYTES)
    result = ExportResult()
    seen: set[str] = set()
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = reader.fieldnames
        if not columns:
            raise ExportFormatError("the file is empty: expected a NextDNS log export (CSV)")
        missing = [name for name in REQUIRED_COLUMNS if name not in columns]
        if missing:
            raise ExportFormatError(
                f"not a NextDNS log export: no {', '.join(missing)} column in the header"
            )
        try:
            for row in reader:
                result.rows += 1
                query_type = (row.get("query_type") or "").strip().upper()
                if not raw and query_type and query_type not in NAVIGATIONAL_TYPES:
                    result.skipped_other_types += 1
                    continue
                reasons = [
                    {"id": reason.strip(), "name": reason.strip()}
                    for reason in (row.get("reasons") or "").split(",")
                    if reason.strip()
                ]
                entry = {
                    "timestamp": row.get("timestamp") or "",
                    "domain": row.get("domain") or "",
                    "status": row.get("status") or "default",
                    "root": row.get("root_domain") or None,
                    "protocol": row.get("protocol") or None,
                    "clientIp": row.get("client_ip") or None,
                    "device": {
                        "id": row.get("device_id") or None,
                        "name": row.get("device_name") or None,
                    },
                    "reasons": reasons,
                    "type": query_type or None,
                }
                try:
                    event = parse_log_entry(profile_id, entry, raw=raw)
                except ValueError:
                    result.skipped_malformed += 1
                    continue
                if event.event_id in seen:
                    result.merged_same_instant += 1
                    continue
                seen.add(event.event_id)
                result.events.append(event)
        except csv.Error as exc:
            raise ExportFormatError(f"the file is not valid CSV: {exc}") from exc
    return result
