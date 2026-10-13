"""OSV collector (scope b): official bucket dumps, incremental via modified_id.csv.

Initial load per ecosystem : <BASE>/<ECO>/all.zip   (ETag-revalidated streaming download)
Incremental                : <BASE>/<ECO>/modified_id.csv  ("<iso modified>,<id>", newest first),
                             then <BASE>/<ECO>/<ID>.json for every id newer than the cursor.
The cursor only advances after a complete, error-free pass, so an interrupted run is simply redone
(upserts are idempotent).
"""

from __future__ import annotations

import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from sqlalchemy import Engine
from sqlalchemy.engine import Connection

from opsgraph.collectors.base import tracked_run
from opsgraph.config import ApprovedSource, LicensePolicy
from opsgraph.http import FetchError, HttpClient
from opsgraph.licensing import UNKNOWN, is_ubuntu_record, license_for_osv_id
from opsgraph.logging import get_logger
from opsgraph.scope import OsvScope
from opsgraph.storage import repository as repo

log = get_logger(__name__)

BASE = "https://storage.googleapis.com/osv-vulnerabilities"
_FRACTION = re.compile(r"(\.\d{6})\d+")


def parse_ts(value: str) -> datetime:
    """OSV timestamps are RFC 3339 and may carry more than 6 fractional digits."""
    return datetime.fromisoformat(_FRACTION.sub(r"\1", value.strip()))


def parse_modified_csv(text: str) -> list[tuple[datetime, str]]:
    rows = []
    for line in text.splitlines():
        ts, sep, osv_id = line.strip().partition(",")
        if not sep or not osv_id:
            continue
        try:
            rows.append((parse_ts(ts), osv_id))
        except ValueError:
            continue
    return rows


class OsvCollector:
    source_id = "osv"

    def __init__(self, http: HttpClient, engine: Engine, scope: OsvScope,
                 source_cfg: ApprovedSource, policy: LicensePolicy, work_dir: Path) -> None:
        self.http, self.engine, self.scope = http, engine, scope
        self.cfg, self.policy, self.work_dir = source_cfg, policy, work_dir

    # ---- discovery --------------------------------------------------------------------------
    def remote_ecosystems(self) -> list[str]:
        res = self.http.get(
            f"{BASE}/ecosystems.txt", ttl=0, min_interval=self.cfg.min_interval_seconds
        )
        if res.status != 200:
            raise FetchError(f"ecosystems.txt returned HTTP {res.status}")
        return [line.strip() for line in res.text.splitlines() if line.strip()]

    # ---- main entry -------------------------------------------------------------------------
    def collect(self, ecosystems: list[str] | None = None, limit: int | None = None,
                dry_run: bool = False) -> repo.CollectStats:
        wanted = ecosystems or self.scope.ecosystems
        excluded = set(self.cfg.exclude_ecosystems)

        def work() -> repo.CollectStats:
            stats = repo.CollectStats()
            remote = set(self.remote_ecosystems())
            for eco in wanted:
                if eco in excluded:
                    stats.notes.append(f"{eco}: excluded by policy")
                    continue
                if eco not in remote:
                    stats.notes.append(f"{eco}: not listed in ecosystems.txt, skipped")
                    stats.errors += 1
                    continue
                stats.merge(self._collect_ecosystem(eco, limit, dry_run))
            return stats

        return tracked_run(self.engine, self.source_id, dry_run, work)

    # ---- per ecosystem ----------------------------------------------------------------------
    def _collect_ecosystem(self, eco: str, limit: int | None, dry_run: bool) -> repo.CollectStats:
        stats = repo.CollectStats()
        with self.engine.begin() as conn:
            cursor_s = repo.get_cursor(conn, self.source_id, eco)
            cursor = parse_ts(cursor_s) if cursor_s else None
            if cursor is None:
                newest, complete = self._initial(eco, conn, stats, limit, dry_run)
            else:
                newest, complete = self._incremental(eco, cursor, conn, stats, limit, dry_run)
            if complete and newest and not stats.errors and not dry_run:
                repo.set_cursor(conn, self.source_id, eco, newest.isoformat())
            elif not complete:
                stats.notes.append(f"{eco}: stopped early (limit); cursor not advanced")
        log.info("osv_ecosystem_done", ecosystem=eco, **stats.as_dict())
        return stats

    def _initial(self, eco: str, conn: Connection, stats: repo.CollectStats,
                 limit: int | None, dry_run: bool) -> tuple[datetime | None, bool]:
        url = f"{BASE}/{quote(eco)}/all.zip"
        dest = self.work_dir / "osv" / eco / "all.zip"
        self.http.download(url, dest, min_interval=self.cfg.min_interval_seconds)
        newest: datetime | None = None
        handled = 0
        with zipfile.ZipFile(dest) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    rec = json.loads(zf.read(name))
                    modified = parse_ts(rec["modified"])
                except (ValueError, KeyError) as e:
                    stats.skipped_other += 1
                    stats.notes.append(f"{eco}/{name}: unreadable ({e})")
                    continue
                newest = modified if newest is None or modified > newest else newest
                if self._process(rec, eco, f"{BASE}/{quote(eco)}/{quote(rec['id'])}.json",
                                 conn, stats, dry_run):
                    handled += 1
                    if limit and handled >= limit:
                        return newest, False
        return newest, True

    def _incremental(self, eco: str, cursor: datetime, conn: Connection, stats: repo.CollectStats,
                     limit: int | None, dry_run: bool) -> tuple[datetime | None, bool]:
        res = self.http.get(f"{BASE}/{quote(eco)}/modified_id.csv", ttl=0,
                            min_interval=self.cfg.min_interval_seconds)
        if res.status != 200:
            raise FetchError(f"{eco}/modified_id.csv returned HTTP {res.status}")
        fresh = sorted((ts, i) for ts, i in parse_modified_csv(res.text) if ts > cursor)
        newest: datetime | None = None
        handled = 0
        for ts, osv_id in fresh:
            url = f"{BASE}/{quote(eco)}/{quote(osv_id)}.json"
            try:
                r = self.http.get(url, ttl=0, min_interval=self.cfg.min_interval_seconds)
            except FetchError as e:
                stats.errors += 1
                stats.notes.append(f"{eco}/{osv_id}: {e}")
                continue
            if r.status != 200:
                stats.skipped_other += 1
                stats.notes.append(f"{eco}/{osv_id}: HTTP {r.status}")
                continue
            newest = ts
            try:
                rec = r.json()
            except ValueError:
                rec = None
            if not isinstance(rec, dict) or "modified" not in rec or "id" not in rec:
                stats.skipped_other += 1
                stats.notes.append(f"{eco}/{osv_id}: not an OSV record")
                continue
            if self._process(rec, eco, url, conn, stats, dry_run):
                handled += 1
                if limit and handled >= limit:
                    return newest, False
        return newest, True

    # ---- one record -------------------------------------------------------------------------
    def _process(self, rec: dict, eco: str, fetch_url: str, conn: Connection,
                 stats: repo.CollectStats, dry_run: bool) -> bool:
        """Returns True when the record was in scope (stored, or counted in a dry run)."""
        if is_ubuntu_record(rec):
            stats.skipped_license += 1
            return False
        license_ = license_for_osv_id(rec["id"])
        if license_ in self.policy.blocked_spdx:
            stats.skipped_license += 1
            return False
        products = self.scope.match(rec)
        if not products:
            stats.skipped_scope += 1
            return False
        if license_ == UNKNOWN:
            stats.unknown_license += 1
        if dry_run:
            stats.would_store += 1
            return True
        result = repo.upsert_osv(
            conn, record=rec, export_ecosystem=eco, products=products, license=license_,
            fetch_url=fetch_url, modified=parse_ts(rec["modified"]),
            published=parse_ts(rec["published"]) if rec.get("published") else None,
            withdrawn=parse_ts(rec["withdrawn"]) if rec.get("withdrawn") else None,
        )
        stats.add(result)
        return True

