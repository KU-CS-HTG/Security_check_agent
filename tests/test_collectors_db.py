"""DESTRUCTIVE: truncates raw.* tables; runs only with OPSGRAPH_ALLOW_TRUNCATE=1.

Collectors against a real PostgreSQL (roles from docker/postgres/init/01-roles.sh, schema from
`alembic upgrade head`). HTTP is mocked, so no internet is needed. Marked integration."""

import os

import httpx
import pytest
from osv_fixtures import (
    DEB_NGINX,
    DEB_OTHER,
    DEB_PG,
    GHSA_NGINX,
    GIT_PG,
    UBUNTU_PG,
    rec,
    zip_bytes,
)
from sqlalchemy import create_engine, text

from opsgraph.collectors.osv import BASE, OsvCollector, parse_modified_csv, parse_ts
from opsgraph.collectors.postgresql_security import (
    INDEX_URL,
    PostgresSecurityCollector,
    extract_cve_urls,
)
from opsgraph.config import HttpSettings, Settings, load_sources
from opsgraph.http import HttpClient
from opsgraph.scope import load_scope

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def settings():
    # These tests TRUNCATE the raw tables. Never let them touch a database holding real data
    # unless the caller opted in explicitly.
    if os.environ.get("OPSGRAPH_ALLOW_TRUNCATE") != "1":
        pytest.skip("destructive DB tests: set OPSGRAPH_ALLOW_TRUNCATE=1 (disposable DB only)")
    s = Settings()
    if not (s.db_owner_password and s.db_collector_password and s.db_reader_password):
        pytest.skip("DB role passwords not configured")
    try:
        probe = create_engine(s.sqlalchemy_url("owner"), connect_args={"connect_timeout": 5})
        with probe.connect() as c:
            c.execute(text("SELECT 1 FROM raw.osv_vulnerability LIMIT 1"))
    except Exception as e:  # not reachable, or `alembic upgrade head` not run
        pytest.skip(f"database/schema not ready: {type(e).__name__}")
    return s


@pytest.fixture
def engine(settings):
    """Collector-role engine (the privileges the real collectors have). Tables start empty."""
    owner = create_engine(settings.sqlalchemy_url("owner"))
    with owner.begin() as c:
        c.execute(text("TRUNCATE raw.osv_vulnerability, raw.web_page, raw.collection_state, "
                       "raw.collection_run RESTART IDENTITY"))
    eng = create_engine(settings.sqlalchemy_url("collector"))
    yield eng
    eng.dispose()
    owner.dispose()


def count(engine, table):
    with engine.connect() as c:
        return c.execute(text(f"SELECT count(*) FROM raw.{table}")).scalar_one()


class FakeBucket:
    """Serves an OSV-like bucket; `files` maps URL -> bytes/str; records requests."""

    def __init__(self, files):
        self.files, self.requests = files, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requests.append(url)
        if url in self.files:
            body = self.files[url]
            return httpx.Response(200, content=body if isinstance(body, bytes) else body.encode(),
                                  headers={"etag": f'"{hash(url) & 0xFFFF}"'})
        return httpx.Response(404)


def make_http(handler, tmp_path):
    cfg = HttpSettings(min_interval_seconds={"default": 0.0}, respect_robots_txt=False,
                       max_retries=1, cache_ttl_seconds=0)
    return HttpClient(cfg, "me@example.com", cache_dir=tmp_path / "cache",
                      transport=httpx.MockTransport(handler), sleep=lambda s: None)


def osv_collector(engine, http, tmp_path):
    sources = load_sources()
    return OsvCollector(http, engine, load_scope(), sources.get("osv"), sources.license_policy,
                        tmp_path / "work")


def deb_files(records, csv_rows=None):
    files = {
        f"{BASE}/ecosystems.txt": "Debian\nAlpine\nGIT\nUbuntu\nPyPI\n",
        f"{BASE}/Debian/all.zip": zip_bytes(records),
    }
    if csv_rows is not None:
        files[f"{BASE}/Debian/modified_id.csv"] = "\n".join(csv_rows)
    return files


def test_initial_load_filters_scope_and_ubuntu_and_records_license(engine, tmp_path):
    files = deb_files([DEB_PG, DEB_NGINX, DEB_OTHER, UBUNTU_PG, GHSA_NGINX])
    col = osv_collector(engine, make_http(FakeBucket(files), tmp_path), tmp_path)
    stats = col.collect(ecosystems=["Debian"])
    assert (stats.inserted, stats.skipped_scope, stats.skipped_license) == (3, 1, 1)
    assert stats.unknown_license == 2  # DSA/DLA ids are UNKNOWN; GHSA is known
    with engine.connect() as c:
        rows = c.execute(text("SELECT osv_id, matched_products, license, source_url "
                              "FROM raw.osv_vulnerability ORDER BY osv_id")).all()
    assert [r[0] for r in rows] == ["DLA-3000-1", "DSA-5000-1", "GHSA-xxxx-yyyy-zzzz"]
    by_id = {r[0]: r for r in rows}
    assert by_id["DSA-5000-1"][1] == ["postgresql"] and by_id["DSA-5000-1"][2] == "UNKNOWN"
    assert by_id["GHSA-xxxx-yyyy-zzzz"][2] == "CC-BY-4.0"
    assert by_id["DSA-5000-1"][3] == "https://osv.dev/vulnerability/DSA-5000-1"
    assert not any(r[0].startswith("UBUNTU") for r in rows)


def test_rerun_is_idempotent_and_changes_are_detected(engine, tmp_path):
    files = deb_files([DEB_PG, DEB_NGINX])
    http = make_http(FakeBucket(files), tmp_path)
    col = osv_collector(engine, http, tmp_path)
    col.collect(ecosystems=["Debian"])
    # cursor is set after the initial load, so a rerun is incremental and finds nothing new
    files[f"{BASE}/Debian/modified_id.csv"] = "2024-03-02T10:00:00Z,DLA-3000-1\n"
    again = col.collect(ecosystems=["Debian"])
    assert again.inserted == again.updated == 0
    assert count(engine, "osv_vulnerability") == 2

    changed = rec("DSA-5000-1", "2024-04-01T00:00:00Z", DEB_PG["affected"], summary="revised")
    files[f"{BASE}/Debian/modified_id.csv"] = (
        "2024-04-01T00:00:00Z,DSA-5000-1\n2024-03-02T10:00:00Z,DLA-3000-1\n"
    )
    import json
    files[f"{BASE}/Debian/DSA-5000-1.json"] = json.dumps(changed)
    third = col.collect(ecosystems=["Debian"])
    assert (third.inserted, third.updated) == (0, 1)
    with engine.connect() as c:
        s = c.execute(text("SELECT payload->>'summary' FROM raw.osv_vulnerability "
                           "WHERE osv_id='DSA-5000-1'")).scalar_one()
    assert s == "revised" and count(engine, "osv_vulnerability") == 2
    # identical content fetched again -> unchanged, no duplicate
    fourth = osv_collector(engine, make_http(FakeBucket(files), tmp_path / "b"), tmp_path)
    with engine.begin() as c:
        c.execute(text("UPDATE raw.collection_state SET cursor='2024-03-31T00:00:00+00:00'"))
    assert fourth.collect(ecosystems=["Debian"]).unchanged == 1


def test_incremental_fetches_only_newer_records(engine, tmp_path):
    files = deb_files([DEB_PG])
    bucket = FakeBucket(files)
    col = osv_collector(engine, make_http(bucket, tmp_path), tmp_path)
    col.collect(ecosystems=["Debian"])  # initial: cursor = 2024-03-01
    import json
    files[f"{BASE}/Debian/modified_id.csv"] = (
        "2024-03-02T10:00:00Z,DLA-3000-1\n2024-03-01T10:00:00Z,DSA-5000-1\n"
    )
    files[f"{BASE}/Debian/DLA-3000-1.json"] = json.dumps(DEB_NGINX)
    bucket.requests.clear()
    stats = col.collect(ecosystems=["Debian"])
    assert stats.inserted == 1
    fetched = [u for u in bucket.requests if u.endswith(".json")]
    assert fetched == [f"{BASE}/Debian/DLA-3000-1.json"]  # DSA-5000-1 is not newer than cursor


def test_limit_does_not_advance_cursor_and_dry_run_writes_nothing(engine, tmp_path):
    files = deb_files([DEB_PG, DEB_NGINX])
    col = osv_collector(engine, make_http(FakeBucket(files), tmp_path), tmp_path)
    dry = col.collect(ecosystems=["Debian"], dry_run=True)
    assert dry.would_store == 2 and count(engine, "osv_vulnerability") == 0
    limited = col.collect(ecosystems=["Debian"], limit=1)
    assert limited.inserted == 1
    with engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM raw.collection_state")).scalar_one() == 0
    full = col.collect(ecosystems=["Debian"])
    assert count(engine, "osv_vulnerability") == 2 and full.unchanged == 1


def test_unknown_and_excluded_ecosystems_are_reported_not_fetched(engine, tmp_path):
    bucket = FakeBucket(deb_files([DEB_PG]))
    col = osv_collector(engine, make_http(bucket, tmp_path), tmp_path)
    stats = col.collect(ecosystems=["Ubuntu", "NoSuchEco"])
    assert stats.errors == 1
    assert any("Ubuntu" in n and "excluded" in n for n in stats.notes)
    assert any("NoSuchEco" in n for n in stats.notes)
    assert not any("all.zip" in u for u in bucket.requests)


def test_run_bookkeeping_and_git_ecosystem(engine, tmp_path):
    files = {f"{BASE}/ecosystems.txt": "GIT\n", f"{BASE}/GIT/all.zip": zip_bytes([GIT_PG])}
    osv_collector(engine, make_http(FakeBucket(files), tmp_path), tmp_path).collect(["GIT"])
    with engine.connect() as c:
        row = c.execute(text("SELECT status, stats->>'inserted' FROM raw.collection_run")).one()
        prods = c.execute(text("SELECT matched_products FROM raw.osv_vulnerability")).scalar_one()
    assert row == ("ok", "1") and prods == ["postgresql"]


def test_parse_helpers():
    assert parse_ts("2024-03-01T10:00:00.123456789Z").microsecond == 123456
    rows = parse_modified_csv("2024-03-02T10:00:00Z,PyPI/X-1\nbroken\n\n2024-03-01T00:00:00Z,B-2\n")
    assert [i for _, i in rows] == ["PyPI/X-1", "B-2"]


# ---- PostgreSQL security pages --------------------------------------------------------------
INDEX_HTML = """
<html><body><table>
<tr><td><a href="/support/security/CVE-2024-0985/">CVE-2024-0985</a></td></tr>
<tr><td><a href="https://www.postgresql.org/support/security/CVE-2023-5868/">CVE-2023-5868</a></td></tr>
<tr><td><a href="/support/security/13/">13</a></td></tr>
<tr><td><a href="/docs/devel/index.html">devel</a></td></tr>
<tr><td><a href="/support/security/CVE-2024-0985/">dup</a></td></tr>
</table></body></html>
"""


def pg_site(tmp_path, pages):
    files = {INDEX_URL: INDEX_HTML, **pages}
    return FakeBucket(files)


def pg_collector(engine, bucket, tmp_path):
    http = make_http(bucket, tmp_path)
    return PostgresSecurityCollector(http, engine, load_sources().get("postgresql"))


def test_extract_cve_urls_only_cve_pages_deduplicated():
    assert extract_cve_urls(INDEX_HTML) == [
        "https://www.postgresql.org/support/security/CVE-2023-5868/",
        "https://www.postgresql.org/support/security/CVE-2024-0985/",
    ]


def test_postgres_pages_stored_once_and_updated_on_change(engine, tmp_path):
    pages = {
        "https://www.postgresql.org/support/security/CVE-2024-0985/": "<h1>CVE-2024-0985</h1>",
        "https://www.postgresql.org/support/security/CVE-2023-5868/": "<h1>CVE-2023-5868</h1>",
    }
    bucket = pg_site(tmp_path, pages)
    col = pg_collector(engine, bucket, tmp_path)
    s1 = col.collect()
    assert s1.inserted == 3 and count(engine, "web_page") == 3  # index + 2 CVE pages
    s2 = col.collect()
    assert (s2.inserted, s2.updated, s2.unchanged) == (0, 0, 3) and count(engine, "web_page") == 3
    bucket.files["https://www.postgresql.org/support/security/CVE-2024-0985/"] = "<h1>revised</h1>"
    s3 = col.collect()
    assert (s3.inserted, s3.updated, s3.unchanged) == (0, 1, 2)
    with engine.connect() as c:
        lic = c.execute(text("SELECT DISTINCT license FROM raw.web_page")).scalar_one()
    assert lic == "PostgreSQL"


def test_postgres_missing_pages_and_limit(engine, tmp_path):
    bucket = pg_site(tmp_path, {})  # CVE pages 404
    stats = pg_collector(engine, bucket, tmp_path).collect()
    assert stats.inserted == 1 and stats.skipped_other == 2  # only the index was stored
    limited = pg_collector(engine, pg_site(tmp_path, {}), tmp_path).collect(limit=1, dry_run=True)
    assert limited.would_store == 1 and limited.skipped_other == 1


def test_collector_role_cannot_delete(engine):
    from sqlalchemy.exc import ProgrammingError
    with pytest.raises(ProgrammingError), engine.begin() as c:
        c.execute(text("DELETE FROM raw.osv_vulnerability"))
