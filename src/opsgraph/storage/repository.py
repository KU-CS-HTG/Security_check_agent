"""Raw-layer persistence. Runs as the *collector* role: INSERT/UPDATE only, never DELETE.

Upserts are keyed by natural keys and skip rows whose content_hash did not change, so re-running
a collection is idempotent. `RETURNING (xmax = 0)` tells an INSERT (True) from an UPDATE (False);
no returned row means "unchanged".
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import Connection

from opsgraph.config import Settings

UpsertResult = Literal["inserted", "updated", "unchanged"]


@dataclass
class CollectStats:
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped_scope: int = 0
    skipped_license: int = 0
    skipped_other: int = 0
    errors: int = 0
    unknown_license: int = 0
    would_store: int = 0  # dry-run only
    notes: list[str] = field(default_factory=list)

    def add(self, result: UpsertResult) -> None:
        setattr(self, result, getattr(self, result) + 1)

    def merge(self, other: CollectStats) -> None:
        for f in ("inserted", "updated", "unchanged", "skipped_scope", "skipped_license",
                  "skipped_other", "errors", "unknown_license", "would_store"):
            setattr(self, f, getattr(self, f) + getattr(other, f))
        self.notes.extend(other.notes)

    def as_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def canonical_hash(obj: Any) -> str:
    """Stable hash of a JSON document (key order and whitespace do not matter)."""
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def make_engine(settings: Settings, role: str = "collector") -> Engine:
    return create_engine(settings.sqlalchemy_url(role), pool_pre_ping=True)  # type: ignore[arg-type]


_OSV_UPSERT = text(
    """
    INSERT INTO raw.osv_vulnerability AS t
      (osv_id, export_ecosystem, modified, published, withdrawn, matched_products, payload,
       content_hash, source_url, fetch_url, license)
    VALUES
      (:osv_id, :export_ecosystem, :modified, :published, :withdrawn, :matched_products,
       CAST(:payload AS jsonb), :content_hash, :source_url, :fetch_url, :license)
    ON CONFLICT (osv_id, export_ecosystem) DO UPDATE SET
      modified = EXCLUDED.modified, published = EXCLUDED.published,
      withdrawn = EXCLUDED.withdrawn, matched_products = EXCLUDED.matched_products,
      payload = EXCLUDED.payload, content_hash = EXCLUDED.content_hash,
      source_url = EXCLUDED.source_url, fetch_url = EXCLUDED.fetch_url,
      license = EXCLUDED.license, collected_at = now()
    WHERE t.content_hash IS DISTINCT FROM EXCLUDED.content_hash
    RETURNING (xmax = 0) AS inserted
    """
)

_PAGE_UPSERT = text(
    """
    INSERT INTO raw.web_page AS t
      (url, source_id, http_status, content_type, body, content_hash, etag, last_modified,
       source_url, license)
    VALUES
      (:url, :source_id, :http_status, :content_type, :body, :content_hash, :etag,
       :last_modified, :source_url, :license)
    ON CONFLICT (url) DO UPDATE SET
      http_status = EXCLUDED.http_status, content_type = EXCLUDED.content_type,
      body = EXCLUDED.body, content_hash = EXCLUDED.content_hash, etag = EXCLUDED.etag,
      last_modified = EXCLUDED.last_modified, license = EXCLUDED.license,
      collected_at = now()
    WHERE t.content_hash IS DISTINCT FROM EXCLUDED.content_hash
    RETURNING (xmax = 0) AS inserted
    """
)


def _result(row) -> UpsertResult:
    if row is None:
        return "unchanged"
    return "inserted" if row[0] else "updated"


def upsert_osv(conn: Connection, *, record: dict, export_ecosystem: str, products: list[str],
               license: str, fetch_url: str, modified: datetime,
               published: datetime | None, withdrawn: datetime | None) -> UpsertResult:
    row = conn.execute(_OSV_UPSERT, {
        "osv_id": record["id"],
        "export_ecosystem": export_ecosystem,
        "modified": modified,
        "published": published,
        "withdrawn": withdrawn,
        "matched_products": sorted(products),
        "payload": json.dumps(record, ensure_ascii=False),
        "content_hash": canonical_hash(record),
        "source_url": f"https://osv.dev/vulnerability/{record['id']}",
        "fetch_url": fetch_url,
        "license": license,
    }).fetchone()
    return _result(row)


def upsert_web_page(conn: Connection, *, url: str, source_id: str, http_status: int,
                    content_type: str | None, body: str, etag: str | None,
                    last_modified: str | None, license: str) -> UpsertResult:
    row = conn.execute(_PAGE_UPSERT, {
        "url": url, "source_id": source_id, "http_status": http_status,
        "content_type": content_type, "body": body,
        "content_hash": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "etag": etag, "last_modified": last_modified, "source_url": url, "license": license,
    }).fetchone()
    return _result(row)


def get_cursor(conn: Connection, source_id: str, key: str) -> str | None:
    row = conn.execute(
        text("SELECT cursor FROM raw.collection_state WHERE source_id=:s AND key=:k"),
        {"s": source_id, "k": key},
    ).fetchone()
    return row[0] if row else None


def set_cursor(conn: Connection, source_id: str, key: str, cursor: str) -> None:
    conn.execute(
        text(
            """INSERT INTO raw.collection_state (source_id, key, cursor) VALUES (:s, :k, :c)
               ON CONFLICT (source_id, key) DO UPDATE SET cursor = EXCLUDED.cursor,
                 updated_at = now()"""
        ),
        {"s": source_id, "k": key, "c": cursor},
    )


def start_run(conn: Connection, source_id: str) -> int:
    return conn.execute(
        text("INSERT INTO raw.collection_run (source_id) VALUES (:s) RETURNING id"),
        {"s": source_id},
    ).scalar_one()


def finish_run(conn: Connection, run_id: int, status: str, stats: CollectStats,
               error: str | None = None) -> None:
    conn.execute(
        text(
            """UPDATE raw.collection_run SET finished_at = now(), status = :st,
               stats = CAST(:stats AS jsonb), error = :err WHERE id = :id"""
        ),
        {"st": status, "stats": json.dumps(stats.as_dict()), "err": error, "id": run_id},
    )
