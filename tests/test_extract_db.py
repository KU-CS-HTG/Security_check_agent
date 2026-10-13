"""DESTRUCTIVE: truncates core.document/extraction tables and raw.web_page; runs only with
OPSGRAPH_ALLOW_TRUNCATE=1. Needs `python -m opsgraph db upgrade` (migration 0005). The LLM is a
scripted fake: this tests persistence, resume, staleness and the role model."""

import json
import os

import pytest
from docs_fixtures import SECTION
from sqlalchemy import create_engine, text
from sqlalchemy.exc import ProgrammingError
from test_extract_runner import FakeLlm, answer, item

from opsgraph.config import Settings, load_sources
from opsgraph.extract.service import run_extraction
from opsgraph.normalize.docs import normalize_docs
from opsgraph.storage import repository as repo

pytestmark = pytest.mark.integration

URL = "https://www.postgresql.org/docs/18/auth-pg-hba-conf.html"
MODEL = "fake-model"
GOOD_QUOTE = "This record matches connection attempts using Unix-domain sockets."


@pytest.fixture(scope="module")
def settings():
    if os.environ.get("OPSGRAPH_ALLOW_TRUNCATE") != "1":
        pytest.skip("destructive DB tests: set OPSGRAPH_ALLOW_TRUNCATE=1 (disposable DB only)")
    s = Settings()
    if not all((s.db_owner_password, s.db_collector_password, s.db_pipeline_password)):
        pytest.skip("DB role passwords not configured")
    try:
        probe = create_engine(s.sqlalchemy_url("owner"), connect_args={"connect_timeout": 5})
        with probe.connect() as c:
            c.execute(text("SELECT 1 FROM core.extracted_item LIMIT 1"))
    except Exception as e:
        pytest.skip(f"database/schema (migration 0005) not ready: {type(e).__name__}")
    return s


@pytest.fixture
def engines(settings):
    owner = create_engine(settings.sqlalchemy_url("owner"))
    with owner.begin() as c:
        c.execute(text("TRUNCATE core.document, core.extraction_run, raw.web_page "
                       "RESTART IDENTITY CASCADE"))
    collector = create_engine(settings.sqlalchemy_url("collector"))
    pipeline = create_engine(settings.sqlalchemy_url("pipeline"))
    with collector.begin() as c:
        repo.upsert_web_page(c, url=URL, source_id="postgresql-docs", http_status=200,
                             content_type="text/html", body=SECTION, etag=None,
                             last_modified=None, license="PostgreSQL")
    normalize_docs(pipeline, load_sources().license_policy)
    yield collector, pipeline
    for e in (collector, pipeline, owner):
        e.dispose()


def one(engine, sql, **kw):
    with engine.connect() as c:
        return c.execute(text(sql), kw).scalar_one()


def first_row(engine, sql, **kw):
    """One row, with the connection closed again (an open transaction would block TRUNCATE)."""
    with engine.connect() as c:
        return c.execute(text(sql), kw).one()


def good(**over):
    base = {"target": "local", "evidence_quote": GOOD_QUOTE, "title": "Unix-domain socket records"}
    return item(**{**base, **over})


def test_run_saves_results_and_items_and_resumes(engines):
    _, pipeline = engines
    llm = FakeLlm(answer(good()), answer())          # two clauses in the fixture page
    stats = run_extraction(pipeline, llm, model=MODEL, min_chars=20)
    assert (stats.selected, stats.processed, stats.ok, stats.empty, stats.failed) == (2, 2, 1, 1, 0)
    assert (stats.items, stats.items_verified) == (1, 1)
    assert one(pipeline, "SELECT count(*) FROM core.extraction_result") == 2
    row = first_row(pipeline, "SELECT status, evidence_verified, evidence_match, target_found, "
                              "payload->>'title' AS item_title FROM core.extracted_item")
    assert (row.status, row.evidence_verified, row.evidence_match, row.target_found) == (
        "pending", True, "exact", True)
    assert row.item_title == "Unix-domain socket records"
    assert one(pipeline, "SELECT status FROM core.extraction_run") == "ok"

    again = run_extraction(pipeline, FakeLlm(), model=MODEL, min_chars=20)  # nothing may be asked
    assert again.selected == 0 and one(pipeline, "SELECT count(*) FROM core.extraction_result") == 2


def test_unverified_items_are_stored_as_rejected(engines):
    _, pipeline = engines
    bad = good(evidence_quote="Always require scram-sha-256 for every connection.")
    run_extraction(pipeline, FakeLlm(answer(bad), answer()), model=MODEL, min_chars=20,
                   max_attempts=1)
    st = first_row(pipeline, "SELECT status, evidence_verified, evidence_match, review_note "
                             "FROM core.extracted_item")
    assert (st.status, st.evidence_verified, st.evidence_match) == ("rejected", False, None)
    assert "not found" in st.review_note


def test_failed_clauses_are_retried_on_the_next_run_force_redoes_all(engines):
    _, pipeline = engines
    run_extraction(pipeline, FakeLlm("junk", answer()), model=MODEL, min_chars=20, max_attempts=1)
    assert one(pipeline, "SELECT count(*) FROM core.extraction_result WHERE status='failed'") == 1
    second = run_extraction(pipeline, FakeLlm(answer(good())), model=MODEL, min_chars=20,
                            max_attempts=1)
    assert second.selected == 1 and second.ok == 1                    # only the failed one
    assert one(pipeline, "SELECT count(*) FROM core.extraction_result") == 2
    assert one(pipeline, "SELECT count(*) FROM core.extraction_result WHERE status='failed'") == 0
    forced = run_extraction(pipeline, FakeLlm(answer(), answer()), model=MODEL, min_chars=20,
                            force=True)
    assert forced.selected == 2 and forced.empty == 2
    assert one(pipeline, "SELECT count(*) FROM core.extraction_result") == 2    # replaced
    assert one(pipeline, "SELECT count(*) FROM core.extracted_item") == 0       # old items gone


def test_changed_clause_text_or_model_or_prompt_makes_results_stale(engines):
    collector, pipeline = engines
    run_extraction(pipeline, FakeLlm(answer(), answer()), model=MODEL, min_chars=20)
    other_model = run_extraction(pipeline, FakeLlm(answer(), answer()), model="other", min_chars=20)
    assert other_model.selected == 2
    other_prompt = run_extraction(pipeline, FakeLlm(answer(), answer()), model=MODEL, min_chars=20,
                                  prompt_version="9")
    assert other_prompt.selected == 2
    with collector.begin() as c:   # the page changes: same clause ids, new text
        repo.upsert_web_page(c, url=URL, source_id="postgresql-docs", http_status=200,
                             content_type="text/html",
                             body=SECTION.replace("TCP/IP", "TCP/IP sockets"), etag=None,
                             last_modified=None, license="PostgreSQL")
    normalize_docs(pipeline, load_sources().license_policy)
    changed = run_extraction(pipeline, FakeLlm(answer()), model=MODEL, min_chars=20)
    assert changed.selected == 1                                       # only the edited clause


def test_page_filter_limit_and_min_chars(engines):
    _, pipeline = engines
    assert run_extraction(pipeline, FakeLlm(), model=MODEL, pages=["no-such-page"]).selected == 0
    assert run_extraction(pipeline, FakeLlm(answer()), model=MODEL, pages=["auth-pg-hba-conf"],
                          limit=1, min_chars=20).processed == 1
    assert run_extraction(pipeline, FakeLlm(), model=MODEL, min_chars=100000).selected == 0


def test_interrupted_run_is_recorded_and_finished_clauses_survive(engines):
    _, pipeline = engines

    class Boom(FakeLlm):
        def chat_json(self, messages, schema):
            if len(self.calls) == 1:
                raise KeyboardInterrupt
            return super().chat_json(messages, schema)

    with pytest.raises(KeyboardInterrupt):
        run_extraction(pipeline, Boom(answer(good()), answer()), model=MODEL, min_chars=20)
    assert one(pipeline, "SELECT status FROM core.extraction_run") == "interrupted"
    assert one(pipeline, "SELECT count(*) FROM core.extraction_result") == 1
    resumed = run_extraction(pipeline, FakeLlm(answer()), model=MODEL, min_chars=20)
    assert resumed.selected == 1


def test_stats_row_matches_what_was_stored(engines):
    _, pipeline = engines
    run_extraction(pipeline, FakeLlm(answer(good()), answer()), model=MODEL, min_chars=20)
    stats = json.loads(json.dumps(one(pipeline, "SELECT stats FROM core.extraction_run")))
    assert (stats["processed"], stats["items_verified"], stats["prompt_tokens"]) == (2, 1, 200)


def test_collector_and_reader_roles_cannot_write_extractions(settings, engines):
    collector, _ = engines
    with pytest.raises(ProgrammingError), collector.begin() as c:
        c.execute(text("DELETE FROM core.extracted_item"))


def test_risk_source_is_document_only_when_the_risk_was_verified(engines):
    _, pipeline = engines
    sentence = "Do not use trust unless you trust every user on the machine."  # in the clause
    kept = good(risk_level="high", risk_quote=sentence, title="Risk with quote")
    dropped = good(risk_level="high", title="Risk without quote")
    run_extraction(pipeline, FakeLlm(answer(kept, dropped), answer()), model=MODEL, min_chars=20)
    with pipeline.connect() as c:
        rows = c.execute(text(
            "SELECT payload->>'title' AS item_title, payload->>'risk_level' AS r, risk_source "
            "FROM core.extracted_item ORDER BY id")).all()
    assert [(r.item_title, r.r, r.risk_source) for r in rows] == [
        ("Risk with quote", "high", "document"), ("Risk without quote", "not_stated", None)]
