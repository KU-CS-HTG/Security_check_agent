"""DESTRUCTIVE: truncates raw.* and core.document; runs only with OPSGRAPH_ALLOW_TRUNCATE=1.
Needs `python -m opsgraph db upgrade` (migration 0004). Collector role writes raw, pipeline role
parses, like in production."""

import os

import httpx
import pytest
from docs_fixtures import CHAPTER, SECTION
from sqlalchemy import create_engine, text

from opsgraph.collectors.postgresql_docs import PostgresDocsCollector
from opsgraph.config import DocsCorpus, HttpSettings, Settings, load_sources
from opsgraph.http import HttpClient
from opsgraph.normalize import docs as docs_mod
from opsgraph.normalize.docs import normalize_docs
from opsgraph.storage import repository as repo

pytestmark = pytest.mark.integration

POLICY = load_sources().license_policy
BASE = "https://www.postgresql.org/docs/18"
HBA = f"{BASE}/auth-pg-hba-conf.html"


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
            c.execute(text("SELECT 1 FROM core.clause LIMIT 1"))
    except Exception as e:
        pytest.skip(f"database/schema (migration 0004) not ready: {type(e).__name__}")
    return s


@pytest.fixture
def engines(settings):
    owner = create_engine(settings.sqlalchemy_url("owner"))
    with owner.begin() as c:
        c.execute(text("TRUNCATE core.document, raw.web_page, raw.collection_run "
                       "RESTART IDENTITY CASCADE"))
    collector = create_engine(settings.sqlalchemy_url("collector"))
    pipeline = create_engine(settings.sqlalchemy_url("pipeline"))
    yield collector, pipeline
    for e in (collector, pipeline, owner):
        e.dispose()


def put(collector, url, html):
    with collector.begin() as c:
        repo.upsert_web_page(c, url=url, source_id="postgresql-docs", http_status=200,
                             content_type="text/html", body=html, etag=None, last_modified=None,
                             license="PostgreSQL")


def one(engine, sql, **kw):
    with engine.connect() as c:
        return c.execute(text(sql), kw).scalar_one()


def clause_ids(engine):
    with engine.connect() as c:
        return dict(c.execute(text("SELECT key, id FROM core.clause")).all())


def test_parse_store_and_rerun(engines):
    collector, pipeline = engines
    put(collector, HBA, SECTION)
    put(collector, f"{BASE}/client-authentication.html", CHAPTER)
    s1 = normalize_docs(pipeline, POLICY)
    assert (s1.documents_inserted, s1.clauses_inserted, s1.errors) == (2, 3, 0)
    with pipeline.connect() as c:
        d = c.execute(text("SELECT * FROM core.document WHERE url = :u"), {"u": HBA}
                      ).mappings().one()
        cl = c.execute(text("SELECT key, ordinal, heading_path, source_url FROM core.clause "
                            "WHERE document_id = :d ORDER BY ordinal"), {"d": d["id"]}).all()
    assert d["title"] == "20.1. The pg_hba.conf File" and d["version"] == "18"
    assert d["license"] == "PostgreSQL" and d["publishable"] is True and d["kogl_type"] is None
    assert "The PostgreSQL Global Development Group" in d["copyright_notice"]
    assert [c.key for c in cl] == ["AUTH-PG-HBA-CONF", "AUTH-PG-HBA-EXAMPLES"]
    assert cl[1].source_url == f"{HBA}#AUTH-PG-HBA-EXAMPLES"

    s2 = normalize_docs(pipeline, POLICY)
    assert (s2.documents_unchanged, s2.documents_inserted, s2.clauses_inserted) == (2, 0, 0)
    assert one(pipeline, "SELECT count(*) FROM core.clause") == 3


def test_clause_ids_survive_rebuilds_and_follow_content_changes(engines, monkeypatch):
    collector, pipeline = engines
    put(collector, HBA, SECTION)
    normalize_docs(pipeline, POLICY)
    before = clause_ids(pipeline)

    s = normalize_docs(pipeline, POLICY, force=True)  # rebuild, same content
    assert (s.clauses_unchanged, s.clauses_inserted, s.clauses_updated) == (2, 0, 0)
    assert clause_ids(pipeline) == before              # ids are stable

    monkeypatch.setattr(docs_mod, "PARSER_VERSION", "next")  # rules changed -> auto rebuild
    assert normalize_docs(pipeline, POLICY).documents_updated == 1
    assert clause_ids(pipeline) == before

    put(collector, HBA, SECTION.replace("scram-sha-256 | salted", "scram | salted")
        .replace("host all all ::1/128      scram-sha-256", "host all all ::1/128 md5"))
    s = normalize_docs(pipeline, POLICY)
    assert (s.clauses_updated, s.clauses_unchanged) == (1, 1)
    assert clause_ids(pipeline) == before              # same clause, new text

    start = SECTION.index('<div class="sect2" id="AUTH-PG-HBA-EXAMPLES">')
    end = SECTION.index('<div class="sect2" id="EMPTY-SECTION">')
    put(collector, HBA, SECTION[:start] + SECTION[end:])  # the Examples section is removed
    s = normalize_docs(pipeline, POLICY)
    assert s.clauses_deleted == 1
    assert set(clause_ids(pipeline)) == {"AUTH-PG-HBA-CONF"}


def test_documents_no_longer_in_the_corpus_are_removed_from_core(engines):
    collector, pipeline = engines
    put(collector, HBA, SECTION)
    put(collector, f"{BASE}/default-roles.html", CHAPTER)
    normalize_docs(pipeline, POLICY, keep_urls={HBA, f"{BASE}/default-roles.html"})
    assert one(pipeline, "SELECT count(*) FROM core.document") == 2
    s = normalize_docs(pipeline, POLICY, keep_urls={HBA})
    assert s.documents_removed == 1 and s.documents_unchanged == 1
    assert one(pipeline, "SELECT count(*) FROM core.document") == 1
    assert one(pipeline, "SELECT count(*) FROM core.clause c JOIN core.document d "
                         "ON d.id = c.document_id WHERE d.url LIKE '%default-roles%'") == 0
    assert one(pipeline, "SELECT count(*) FROM raw.web_page") == 2  # raw is never touched


def test_page_without_clauses_is_reported(engines):
    collector, pipeline = engines
    put(collector, f"{BASE}/empty.html", "<html><body><div id='docContent'></div></body></html>")
    s = normalize_docs(pipeline, POLICY)
    assert s.documents_inserted == 1 and any("no clauses" in n for n in s.notes)


def test_pipeline_role_cannot_modify_raw_pages(engines):
    from sqlalchemy.exc import ProgrammingError
    _, pipeline = engines
    with pytest.raises(ProgrammingError), pipeline.begin() as c:
        c.execute(text("DELETE FROM raw.web_page"))


# ---- collector (HTTP mocked) --------------------------------------------------------------
def make_collector(collector_engine, tmp_path, pages, files):
    def handler(request: httpx.Request) -> httpx.Response:
        body = files.get(str(request.url))
        return httpx.Response(200, text=body) if body is not None else httpx.Response(404)

    cfg = HttpSettings(min_interval_seconds={"default": 0.0}, respect_robots_txt=False,
                       max_retries=1, cache_ttl_seconds=0)
    http = HttpClient(cfg, "me@example.com", cache_dir=tmp_path / "c",
                      transport=httpx.MockTransport(handler), sleep=lambda s: None)
    return PostgresDocsCollector(http, collector_engine, load_sources().get("postgresql"),
                                 DocsCorpus(version="18", pages=pages))


def test_collector_stores_pages_reports_missing_and_is_idempotent(engines, tmp_path):
    collector, pipeline = engines
    files = {HBA: SECTION, f"{BASE}/client-authentication.html": CHAPTER}
    col = make_collector(collector, tmp_path, ["auth-pg-hba-conf", "client-authentication",
                                               "no-such-page"], files)
    s1 = col.collect()
    assert (s1.inserted, s1.skipped_other) == (2, 1)
    assert any("no-such-page" in n and "404" in n for n in s1.notes)
    s2 = col.collect()
    assert (s2.inserted, s2.updated, s2.unchanged) == (0, 0, 2)
    assert one(pipeline, "SELECT count(*) FROM raw.web_page WHERE source_id='postgresql-docs'") == 2
    assert one(pipeline, "SELECT status FROM raw.collection_run ORDER BY id DESC LIMIT 1") == "ok"


def test_collector_respects_source_rules_for_devel_docs(engines, tmp_path):
    collector, _ = engines
    corpus_url = "https://www.postgresql.org/docs/devel/auth-pg-hba-conf.html"
    col = make_collector(collector, tmp_path, ["auth-pg-hba-conf"], {corpus_url: SECTION})
    col.corpus = DocsCorpus(version="devel", pages=["auth-pg-hba-conf"])
    stats = col.collect()
    assert stats.skipped_other == 1 and stats.inserted == 0
    assert "not allowed by source rules" in stats.notes[0]
