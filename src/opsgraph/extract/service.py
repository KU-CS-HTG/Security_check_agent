"""Run extraction over stored clauses and persist results (pipeline role).

Every clause is committed on its own, so an interrupted run loses nothing and the next run resumes:
a clause is skipped when a non-failed result exists for (clause text, model, prompt version).
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import Engine, text
from sqlalchemy.engine import Connection

from opsgraph.extract.prompt import PROMPT_VERSION
from opsgraph.extract.runner import ChatJson, Outcome, extract_clause
from opsgraph.extract.schema import SCHEMA_VERSION
from opsgraph.logging import get_logger

log = get_logger(__name__)


@dataclass
class ExtractStats:
    selected: int = 0
    processed: int = 0
    ok: int = 0
    empty: int = 0
    failed: int = 0
    retried: int = 0           # clauses that needed more than one attempt
    items: int = 0
    items_verified: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    seconds: float = 0.0

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


@dataclass
class ClauseRow:
    id: int
    key: str
    text: str
    text_hash: str
    heading_path: list[str]
    source_url: str
    doc_title: str | None
    doc_url: str


Progress = Callable[[int, int, ClauseRow, Outcome], None]


def select_clauses(conn: Connection, *, model: str, prompt_version: str, pages: list[str] | None,
                   min_chars: int, force: bool, limit: int | None) -> list[ClauseRow]:
    page_re = "/(" + "|".join(re.escape(p) for p in pages) + r")\.html$" if pages else None
    rows = conn.execute(text("""
        SELECT c.id, c.key, c.text, c.text_hash, c.heading_path, c.source_url,
               d.title AS doc_title, d.url AS doc_url
        FROM core.clause c JOIN core.document d ON d.id = c.document_id
        WHERE length(c.text) >= :min_chars
          AND (CAST(:page_re AS text) IS NULL OR d.url ~ CAST(:page_re AS text))
          AND (:force OR NOT EXISTS (
                SELECT 1 FROM core.extraction_result r
                WHERE r.clause_id = c.id AND r.text_hash = c.text_hash
                  AND r.model = :model AND r.prompt_version = :pv AND r.status <> 'failed'))
        ORDER BY d.url, c.ordinal
        LIMIT :lim"""), {"min_chars": min_chars, "page_re": page_re, "force": force,
                         "model": model, "pv": prompt_version, "lim": limit}).mappings().all()
    return [ClauseRow(**dict(r)) for r in rows]


def save_outcome(conn: Connection, run_id: int, clause: ClauseRow, out: Outcome, *, model: str,
                 prompt_version: str) -> None:
    conn.execute(text("""DELETE FROM core.extraction_result WHERE clause_id = :c AND text_hash = :h
                         AND model = :m AND prompt_version = :pv"""),
                 {"c": clause.id, "h": clause.text_hash, "m": model, "pv": prompt_version})
    result_id = conn.execute(text("""
        INSERT INTO core.extraction_result
          (run_id, clause_id, text_hash, model, prompt_version, schema_version, status, attempts,
           error, raw_response, prompt_tokens, completion_tokens, duration_ms)
        VALUES (:run, :clause, :hash, :model, :pv, :sv, :status, :attempts, :error, :raw, :pt, :ct,
                :ms) RETURNING id"""), {
        "run": run_id, "clause": clause.id, "hash": clause.text_hash, "model": model,
        "pv": prompt_version, "sv": SCHEMA_VERSION, "status": out.status,
        "attempts": out.attempts, "error": out.error, "raw": out.raw_response,
        "pt": out.prompt_tokens, "ct": out.completion_tokens, "ms": out.duration_ms}).scalar_one()
    for item in out.items:
        verified = item.verified
        note = None if verified else "auto: quoted text not found in the clause"
        conn.execute(text("""
            INSERT INTO core.extracted_item
              (result_id, clause_id, payload, evidence_quote, evidence_match, remediation_match,
               target_found, evidence_verified, status, risk_source, review_note)
            VALUES (:result, :clause, CAST(:payload AS jsonb), :quote, :em, :rm, :tf, :ev, :st,
                    :rs, :note)"""), {
            "result": result_id, "clause": clause.id,
            "payload": json.dumps(item.payload, ensure_ascii=False),
            "quote": item.payload["evidence_quote"], "em": item.evidence_match,
            "rm": item.remediation_match, "tf": item.target_found, "ev": verified,
            "st": "pending" if verified else "rejected",
            "rs": "document" if item.payload.get("risk_level") != "not_stated" else None,
            "note": note})


def run_extraction(engine: Engine, llm: ChatJson, *, model: str, pages: list[str] | None = None,
                   limit: int | None = None, min_chars: int = 80, force: bool = False,
                   max_attempts: int = 3, prompt_version: str = PROMPT_VERSION,
                   on_progress: Progress | None = None) -> ExtractStats:
    stats = ExtractStats()
    with engine.begin() as conn:
        clauses = select_clauses(conn, model=model, prompt_version=prompt_version, pages=pages,
                                 min_chars=min_chars, force=force, limit=limit)
        run_id = conn.execute(text("""
            INSERT INTO core.extraction_run (model, prompt_version, schema_version, params)
            VALUES (:m, :pv, :sv, CAST(:p AS jsonb)) RETURNING id"""), {
            "m": model, "pv": prompt_version, "sv": SCHEMA_VERSION,
            "p": json.dumps({"pages": pages, "limit": limit, "min_chars": min_chars,
                             "force": force, "max_attempts": max_attempts})}).scalar_one()
    stats.selected = len(clauses)
    started = time.monotonic()
    status = "ok"
    try:
        for i, clause in enumerate(clauses, 1):
            out = extract_clause(llm, doc_title=clause.doc_title,
                                 heading_path=clause.heading_path, source_url=clause.source_url,
                                 text=clause.text, max_attempts=max_attempts)
            with engine.begin() as conn:
                save_outcome(conn, run_id, clause, out, model=model, prompt_version=prompt_version)
            stats.processed += 1
            setattr(stats, out.status, getattr(stats, out.status) + 1)
            stats.retried += out.attempts > 1
            stats.items += len(out.items)
            stats.items_verified += sum(1 for it in out.items if it.verified)
            stats.prompt_tokens += out.prompt_tokens
            stats.completion_tokens += out.completion_tokens
            if on_progress:
                on_progress(i, len(clauses), clause, out)
    except KeyboardInterrupt:
        status = "interrupted"
        raise
    except Exception:
        status = "failed"
        raise
    finally:
        stats.seconds = round(time.monotonic() - started, 1)
        with engine.begin() as conn:
            conn.execute(text("""UPDATE core.extraction_run SET finished_at = now(),
                                 status = :s, stats = CAST(:st AS jsonb) WHERE id = :id"""),
                         {"s": status, "st": json.dumps(stats.as_dict()), "id": run_id})
    return stats
