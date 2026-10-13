"""DESTRUCTIVE: truncates raw.* and core.*; runs only with OPSGRAPH_ALLOW_TRUNCATE=1.

raw rows are written with the collector role (as the real collectors do), normalization runs
with the pipeline role (as in production): this exercises the privilege model end to end.
Needs `python -m opsgraph db upgrade` (migration 0002).
"""

import os

import pytest
from osv_fixtures import DEB_NGINX, DEB_PG, rec
from sqlalchemy import create_engine, text
from test_normalize import PAGE_LEGACY, PAGE_REAL, PAGE_SPARSE

from opsgraph.collectors.osv import parse_ts
from opsgraph.config import Settings, load_sources
from opsgraph.normalize.osv import normalize_osv
from opsgraph.normalize.pg_advisory import normalize_pg_advisories, parse_coverage
from opsgraph.storage import repository as repo

pytestmark = pytest.mark.integration

POLICY = load_sources().license_policy
BASE = "https://www.postgresql.org/support/security"
VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


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
            c.execute(text("SELECT 1 FROM core.pg_advisory LIMIT 1"))
    except Exception as e:
        pytest.skip(f"database/schema (migration 0002) not ready: {type(e).__name__}")
    return s


@pytest.fixture
def engines(settings):
    owner = create_engine(settings.sqlalchemy_url("owner"))
    with owner.begin() as c:
        c.execute(text("TRUNCATE core.vulnerability, core.pg_advisory, raw.osv_vulnerability, "
                       "raw.web_page RESTART IDENTITY CASCADE"))
    collector = create_engine(settings.sqlalchemy_url("collector"))
    pipeline = create_engine(settings.sqlalchemy_url("pipeline"))
    yield collector, pipeline, owner
    for e in (collector, pipeline, owner):
        e.dispose()


def put_osv(collector, record, eco, products=("nginx",), license_="UNKNOWN", modified=None):
    with collector.begin() as c:
        return repo.upsert_osv(
            c, record=record, export_ecosystem=eco, products=list(products), license=license_,
            fetch_url=f"https://x/{eco}/{record['id']}.json",
            modified=modified or parse_ts(record["modified"]), published=None, withdrawn=None)


def put_page(collector, cve, html):
    with collector.begin() as c:
        repo.upsert_web_page(c, url=f"{BASE}/{cve}/", source_id="postgresql", http_status=200,
                             content_type="text/html", body=html, etag=None, last_modified=None,
                             license="PostgreSQL")


def scalar(engine, sql, **kw):
    with engine.connect() as c:
        return c.execute(text(sql), kw).scalar_one()


def ranges_of(engine, osv_id):
    return scalar(engine, "SELECT count(*) FROM core.version_range r JOIN core.affected_package a "
                          "ON a.id = r.affected_id WHERE a.osv_id = :i", i=osv_id)


def test_osv_end_to_end_and_idempotent(engines):
    collector, pipeline, _ = engines
    ghsa = rec("GHSA-aaaa-bbbb-cccc", "2024-05-01T00:00:00Z", [
        {"package": {"ecosystem": "Debian:12", "name": "nginx"},
         "ranges": [{"type": "ECOSYSTEM", "events": [
             {"introduced": "0"}, {"fixed": "1.22.1-9"}, {"introduced": "2.0"}, {"fixed": "2.3"}]}],
         "versions": ["1.18"]}],
        aliases=["CVE-2024-9"], severity=[{"type": "CVSS_V3", "score": VEC}],
        references=[{"type": "ADVISORY", "url": "https://example.org/adv"}])
    put_osv(collector, ghsa, "Debian", license_="CC-BY-4.0")
    put_osv(collector, ghsa, "Alpine", license_="CC-BY-4.0")  # same id exported twice
    put_osv(collector, DEB_PG, "Debian", products=("postgresql",))
    put_osv(collector, DEB_NGINX, "Debian")

    s1 = normalize_osv(pipeline, POLICY)
    assert (s1.processed, s1.inserted, s1.unchanged, s1.errors) == (3, 3, 0, 0)
    assert scalar(pipeline, "SELECT count(*) FROM core.vulnerability") == 3
    with pipeline.connect() as c:
        v = c.execute(text("SELECT * FROM core.vulnerability WHERE osv_id='GHSA-aaaa-bbbb-cccc'")
                      ).mappings().one()
    assert v["export_ecosystems"] == ["Alpine", "Debian"] and v["aliases"] == ["CVE-2024-9"]
    assert (float(v["severity_score"]), v["severity_label"]) == (9.8, "CRITICAL")
    assert v["publishable"] is True and v["license"] == "CC-BY-4.0"
    unknown = scalar(pipeline, "SELECT publishable FROM core.vulnerability "
                               "WHERE osv_id = 'DSA-5000-1'")
    assert unknown is False  # an UNKNOWN license is never publishable
    assert ranges_of(pipeline, "GHSA-aaaa-bbbb-cccc") == 2
    assert scalar(pipeline, "SELECT count(*) FROM core.vuln_reference") == 1

    s2 = normalize_osv(pipeline, POLICY)  # nothing changed in raw
    assert (s2.inserted, s2.updated, s2.unchanged) == (0, 0, 3)
    assert ranges_of(pipeline, "GHSA-aaaa-bbbb-cccc") == 2  # not duplicated by the rerun

    changed = dict(ghsa, summary="revised", modified="2024-06-01T00:00:00Z",
                   affected=[{"package": {"ecosystem": "Debian:12", "name": "nginx"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [
                                  {"introduced": "0"}, {"fixed": "9.9"}]}]}])
    put_osv(collector, changed, "Debian", license_="CC-BY-4.0")
    s3 = normalize_osv(pipeline, POLICY)
    assert (s3.inserted, s3.updated, s3.unchanged) == (0, 1, 2)
    # children were replaced, not accumulated
    assert ranges_of(pipeline, "GHSA-aaaa-bbbb-cccc") == 1
    assert scalar(pipeline, "SELECT summary FROM core.vulnerability "
                            "WHERE osv_id='GHSA-aaaa-bbbb-cccc'") == "revised"

    s4 = normalize_osv(pipeline, POLICY, force=True)
    assert s4.updated == 3 and scalar(pipeline, "SELECT count(*) FROM core.vulnerability") == 3


def test_osv_one_bad_record_does_not_stop_the_run(engines):
    collector, pipeline, _ = engines
    put_osv(collector, DEB_PG, "Debian", products=("postgresql",))
    # payload with an unparsable timestamp: raw accepts it (verbatim), normalization must not
    bad = dict(DEB_NGINX, modified="not-a-date")
    put_osv(collector, bad, "Debian", modified=parse_ts("2024-03-02T10:00:00Z"))
    stats = normalize_osv(pipeline, POLICY)
    assert (stats.processed, stats.inserted, stats.errors) == (2, 1, 1)
    assert "DLA-3000-1" in stats.notes[0]
    assert scalar(pipeline, "SELECT count(*) FROM core.vulnerability") == 1
    assert scalar(pipeline, "SELECT osv_id FROM core.vulnerability") == "DSA-5000-1"


def test_pg_pages_end_to_end_and_coverage(engines):
    collector, pipeline, _ = engines
    put_page(collector, "CVE-2024-0985", PAGE_LEGACY)
    put_page(collector, "CVE-2022-1552", PAGE_REAL)
    put_page(collector, "CVE-2019-0001", PAGE_SPARSE)
    with collector.begin() as c:  # the index page is stored too, but is not an advisory
        repo.upsert_web_page(c, url=f"{BASE}/", source_id="postgresql", http_status=200,
                             content_type="text/html", body="<html>index</html>", etag=None,
                             last_modified=None, license="PostgreSQL")
    s1 = normalize_pg_advisories(pipeline, POLICY)
    assert (s1.processed, s1.inserted, s1.errors) == (3, 3, 0)
    with pipeline.connect() as c:
        row = c.execute(text("SELECT * FROM core.pg_advisory WHERE cve_id='CVE-2022-1552'")
                        ).mappings().one()
        versions = c.execute(text("SELECT affected_major, fixed_in, fix_published "
                                  "FROM core.pg_advisory_version WHERE cve_id='CVE-2022-1552' "
                                  "ORDER BY ordinal")).all()
    assert row["fixed_versions"] == ["14.3", "13.7", "12.11", "11.16", "10.21"]
    assert float(row["cvss_score"]) == 8.8 and row["cvss_version"] == "3.0"
    assert row["publishable"] is True and row["source_url"] == f"{BASE}/CVE-2022-1552/"
    assert [(v[0], v[1], str(v[2])) for v in versions][-1] == ("10", "10.21", "2022-05-12")
    assert len(versions) == 5

    cov = parse_coverage(pipeline)
    assert cov["title"] == (3, 3) and cov["fixed"] == (2, 3) and cov["cvss_vector"] == (2, 3)
    assert cov["version_table"] == (1, 3) and cov["score_mismatch (should be 0)"] == (0, 3)

    s2 = normalize_pg_advisories(pipeline, POLICY)
    assert (s2.inserted, s2.updated, s2.unchanged) == (0, 0, 3)
    assert scalar(pipeline, "SELECT count(*) FROM core.pg_advisory_version") == 5  # no duplicates
    put_page(collector, "CVE-2022-1552", PAGE_REAL.replace("14.3", "14.4"))
    s3 = normalize_pg_advisories(pipeline, POLICY)
    assert (s3.updated, s3.unchanged) == (1, 2)
    assert scalar(pipeline, "SELECT count(*) FROM core.pg_advisory_version") == 5  # replaced
    assert scalar(pipeline, "SELECT fixed_in FROM core.pg_advisory_version "
                            "WHERE cve_id='CVE-2022-1552' AND ordinal=0") == "14.4"


def test_parser_version_change_triggers_rebuild(engines, monkeypatch):
    collector, pipeline, _ = engines
    put_page(collector, "CVE-2022-1552", PAGE_REAL)
    assert normalize_pg_advisories(pipeline, POLICY).inserted == 1
    assert normalize_pg_advisories(pipeline, POLICY).unchanged == 1
    from opsgraph.normalize import pg_advisory
    monkeypatch.setattr(pg_advisory, "PARSER_VERSION", "next")
    assert normalize_pg_advisories(pipeline, POLICY).updated == 1  # raw unchanged, rules changed


def test_pipeline_role_cannot_touch_raw(engines):
    from sqlalchemy.exc import ProgrammingError
    _, pipeline, _ = engines
    with pytest.raises(ProgrammingError), pipeline.begin() as c:
        c.execute(text("DELETE FROM raw.web_page"))
