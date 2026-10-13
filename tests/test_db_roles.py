"""Privilege matrix of the three DB roles. Needs a running DB initialised by
docker/postgres/init/01-roles.sh (see docs/ops/SETUP.md). Skipped when DB env is not set.

Run:  pytest -m integration   (env from .env: POSTGRES_HOST, DB_*_USER/PASSWORD)
"""
import os
import uuid

import psycopg
import pytest

from opsgraph.config import Settings

pytestmark = pytest.mark.integration

# A hung connection must fail fast instead of freezing the test run.
CONNECT_TIMEOUT = 5
STATEMENT_TIMEOUT_MS = 10_000


def connect(settings: Settings, role: str, **kw):
    return psycopg.connect(
        settings.dsn(role),
        connect_timeout=CONNECT_TIMEOUT,
        options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS}",
        **kw,
    )


@pytest.fixture(scope="module")
def settings():
    s = Settings(_env_file=".env") if os.path.exists(".env") else Settings()
    if not (s.db_owner_password and s.db_collector_password and s.db_reader_password):
        pytest.skip("DB role passwords not configured")
    try:
        connect(s, "owner").close()
    except psycopg.OperationalError as e:
        pytest.skip(f"database not reachable: {e}")
    return s


@pytest.fixture(scope="module")
def table(settings):
    name = f"t_{uuid.uuid4().hex[:8]}"
    with connect(settings, "owner", autocommit=True) as c:
        c.execute(f"CREATE TABLE raw.{name} (id serial PRIMARY KEY, v text)")
        c.execute(f"CREATE TABLE core.{name} (id int)")
        yield name
        c.execute(f"DROP TABLE raw.{name}")
        c.execute(f"DROP TABLE core.{name}")


def run(settings, role, sql):
    with connect(settings, role, autocommit=True) as c:
        cur = c.execute(sql)
        return cur.fetchall() if cur.description else None


@pytest.mark.parametrize(
    "role,sql_tpl,allowed",
    [
        ("collector", "INSERT INTO raw.{t}(v) VALUES ('x')", True),
        ("collector", "UPDATE raw.{t} SET v='y'", True),
        ("collector", "DELETE FROM raw.{t}", False),
        ("collector", "SELECT * FROM core.{t}", False),
        ("collector", "CREATE TABLE raw.zz(i int)", False),
        ("reader", "SELECT * FROM raw.{t}", True),
        ("reader", "SELECT * FROM core.{t}", True),
        ("reader", "INSERT INTO raw.{t}(v) VALUES ('z')", False),
        ("reader", "CREATE TABLE public.zz(i int)", False),
    ],
)
def test_privilege_matrix(settings, table, role, sql_tpl, allowed):
    sql = sql_tpl.format(t=table)
    if allowed:
        run(settings, role, sql)
    else:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            run(settings, role, sql)
