"""PostgreSQL documentation pages listed in config/docs_corpus.yaml (corpus A).

Stored as raw HTML in raw.web_page (source label `postgresql-docs`, license `PostgreSQL`). Every URL
passes the source rules of config/sources.yaml (docs/<version>/ allowed, docs/devel/ denied) and
robots.txt. Missing pages (HTTP 404) are reported, not guessed.
"""

from __future__ import annotations

from sqlalchemy import Engine

from opsgraph.collectors.base import tracked_run
from opsgraph.config import ApprovedSource, DocsCorpus
from opsgraph.http import HttpClient
from opsgraph.logging import get_logger
from opsgraph.storage import repository as repo

log = get_logger(__name__)

SOURCE_LABEL = "postgresql-docs"
LICENSE = "PostgreSQL"


class PostgresDocsCollector:
    def __init__(self, http: HttpClient, engine: Engine, source_cfg: ApprovedSource,
                 corpus: DocsCorpus) -> None:
        self.http, self.engine, self.cfg, self.corpus = http, engine, source_cfg, corpus

    def collect(self, limit: int | None = None, dry_run: bool = False) -> repo.CollectStats:
        def work() -> repo.CollectStats:
            stats = repo.CollectStats()
            urls = self.corpus.urls()[:limit] if limit else self.corpus.urls()
            with self.engine.begin() as conn:
                for url in urls:
                    if not self.cfg.url_allowed(url):
                        stats.skipped_other += 1
                        stats.notes.append(f"{url}: not allowed by source rules")
                        continue
                    res = self.http.get(url, min_interval=self.cfg.min_interval_seconds)
                    if res.status != 200:
                        stats.skipped_other += 1
                        stats.notes.append(f"{url}: HTTP {res.status} (check the page name)")
                        continue
                    if dry_run:
                        stats.would_store += 1
                        continue
                    hdr = {k.lower(): v for k, v in res.headers.items()}
                    stats.add(repo.upsert_web_page(
                        conn, url=url, source_id=SOURCE_LABEL, http_status=res.status,
                        content_type=hdr.get("content-type"), body=res.text,
                        etag=hdr.get("etag"), last_modified=hdr.get("last-modified"),
                        license=LICENSE))
            return stats

        return tracked_run(self.engine, SOURCE_LABEL, dry_run, work)
