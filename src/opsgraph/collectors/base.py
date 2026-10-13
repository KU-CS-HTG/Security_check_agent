"""Shared collector plumbing: run bookkeeping around a unit of collection work."""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import Engine

from opsgraph.logging import get_logger
from opsgraph.storage import repository as repo

log = get_logger(__name__)


def tracked_run(
    engine: Engine, source_id: str, dry_run: bool, work: Callable[[], repo.CollectStats]
) -> repo.CollectStats:
    """Record the run in raw.collection_run (own transactions, so failures are still logged)."""
    if dry_run:
        return work()
    with engine.begin() as conn:
        run_id = repo.start_run(conn, source_id)
    try:
        stats = work()
    except Exception as e:
        with engine.begin() as conn:
            repo.finish_run(conn, run_id, "failed", repo.CollectStats(), error=repr(e))
        raise
    status = "partial" if stats.errors else "ok"
    with engine.begin() as conn:
        repo.finish_run(conn, run_id, status, stats)
    log.info("collection_finished", source=source_id, status=status, **stats.as_dict())
    return stats
