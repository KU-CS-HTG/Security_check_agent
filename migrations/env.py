"""Alembic environment. Migrations run as the owner role (DDL); version table lives in `core`
because the owner does not own the `public` schema."""

from alembic import context
from sqlalchemy import create_engine, pool, text

from opsgraph.config import get_settings

target_metadata = None
VERSION_SCHEMA = "core"


def protect_version_table(conn) -> None:
    """Default privileges would let the pipeline role write core.alembic_version; take that back."""
    role = get_settings().db_pipeline_user
    stmt = conn.execute(
        text("SELECT format('REVOKE INSERT, UPDATE, DELETE ON core.alembic_version FROM %I', "
             "rolname) FROM pg_roles WHERE rolname = :r"),
        {"r": role},
    ).scalar()
    if stmt:
        conn.execute(text(stmt))
    conn.commit()


def run_migrations() -> None:
    engine = create_engine(
        get_settings().sqlalchemy_url("owner"),
        poolclass=pool.NullPool,
        connect_args={"connect_timeout": 10},
    )
    with engine.connect() as conn:
        context.configure(
            connection=conn,
            target_metadata=target_metadata,
            version_table_schema=VERSION_SCHEMA,
        )
        with context.begin_transaction():
            context.run_migrations()
        protect_version_table(conn)


run_migrations()
