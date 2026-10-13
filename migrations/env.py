"""Alembic environment. Migrations run as the owner role (DDL); version table lives in `core`
because the owner does not own the `public` schema."""

from alembic import context
from sqlalchemy import create_engine, pool

from opsgraph.config import get_settings

target_metadata = None
VERSION_SCHEMA = "core"


def run_migrations() -> None:
    engine = create_engine(get_settings().sqlalchemy_url("owner"), poolclass=pool.NullPool)
    with engine.connect() as conn:
        context.configure(
            connection=conn,
            target_metadata=target_metadata,
            version_table_schema=VERSION_SCHEMA,
        )
        with context.begin_transaction():
            context.run_migrations()


run_migrations()
