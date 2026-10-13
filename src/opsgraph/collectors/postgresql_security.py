"""PostgreSQL project security pages (https://www.postgresql.org/support/security/).

Stores the index page and every per-CVE page it links to as raw HTML (license: PostgreSQL License;
the copyright notice requirement is kept in docs/sources/SOURCES.md and `source_url` is stored with
every page). Unchanged pages are detected by content hash, so re-runs are idempotent. Every URL is
checked against the source's allow/deny prefixes (config/sources.yaml) and robots.txt.
"""

from __future__ import annotations

import re

from sqlalchemy import Engine

from opsgraph.collectors.base import tracked_run
from opsgraph.config import ApprovedSource
from opsgraph.http import FetchError, HttpClient
from opsgraph.logging import get_logger
from opsgraph.storage import repository as repo

log = get_logger(__name__)

INDEX_URL = "https://www.postgresql.org/support/security/"
ORIGIN = "https://www.postgresql.org"
LICENSE = "PostgreSQL"
_CVE_LINK = re.compile(
    r"""href=["'](?:https://www\.postgresql\.org)?(/support/security/CVE-\d{4}-\d{4,7}/?)["']""",
    re.IGNORECASE,
)


def extract_cve_urls(index_html: str) -> list[str]:
    urls = {ORIGIN + m.group(1).rstrip("/") + "/" for m in _CVE_LINK.finditer(index_html)}
    return sorted(urls)


class PostgresSecurityCollector:
    source_id = "postgresql"

    def __init__(self, http: HttpClient, engine: Engine, source_cfg: ApprovedSource) -> None:
        self.http, self.engine, self.cfg = http, engine, source_cfg

    def collect(self, limit: int | None = None, dry_run: bool = False) -> repo.CollectStats:
        def work() -> repo.CollectStats:
            stats = repo.CollectStats()
            index = self._fetch(INDEX_URL, ttl=0)
            if index is None or index.status != 200:
                raise FetchError(f"security index not available: {getattr(index, 'status', None)}")
            urls = extract_cve_urls(index.text)
            if not urls:
                stats.errors += 1
                stats.notes.append("no CVE links found on the index page (page layout changed?)")
            targets = [INDEX_URL, *(urls[:limit] if limit else urls)]
            with self.engine.begin() as conn:
                for url in targets:
                    res = index if url == INDEX_URL else self._fetch(url)
                    self._store(conn, url, res, stats, dry_run)
            return stats

        return tracked_run(self.engine, self.source_id, dry_run, work)

    def _fetch(self, url: str, ttl: int | None = None):
        if not self.cfg.url_allowed(url):
            return None
        return self.http.get(url, ttl=ttl, min_interval=self.cfg.min_interval_seconds)

    def _store(self, conn, url: str, res, stats: repo.CollectStats, dry_run: bool) -> None:
        if res is None:
            stats.skipped_other += 1
            stats.notes.append(f"{url}: not allowed by source rules")
            return
        if res.status != 200:
            stats.skipped_other += 1
            stats.notes.append(f"{url}: HTTP {res.status}")
            return
        if dry_run:
            stats.would_store += 1
            return
        hdr = {k.lower(): v for k, v in res.headers.items()}
        stats.add(repo.upsert_web_page(
            conn, url=url, source_id=self.source_id, http_status=res.status,
            content_type=hdr.get("content-type"), body=res.text, etag=hdr.get("etag"),
            last_modified=hdr.get("last-modified"), license=LICENSE,
        ))
