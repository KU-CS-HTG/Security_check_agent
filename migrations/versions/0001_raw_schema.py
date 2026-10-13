"""raw schema: collection bookkeeping, OSV records, fetched web pages

Revision ID: 0001
Revises:
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "collection_run",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("source_id", sa.Text, nullable=False),
        sa.Column("started_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", TS),
        sa.Column("status", sa.Text, nullable=False, server_default="running"),
        sa.Column("stats", pg.JSONB),
        sa.Column("error", sa.Text),
        schema="raw",
    )
    # Incremental watermarks, e.g. (osv, Debian) -> last processed `modified` timestamp
    op.create_table(
        "collection_state",
        sa.Column("source_id", sa.Text, nullable=False),
        sa.Column("key", sa.Text, nullable=False),
        sa.Column("cursor", sa.Text, nullable=False),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("source_id", "key"),
        schema="raw",
    )
    op.create_table(
        "osv_vulnerability",
        sa.Column("osv_id", sa.Text, nullable=False),
        sa.Column("export_ecosystem", sa.Text, nullable=False),
        sa.Column("modified", TS, nullable=False),
        sa.Column("published", TS),
        sa.Column("withdrawn", TS),
        sa.Column("matched_products", pg.ARRAY(sa.Text), nullable=False),
        sa.Column("payload", pg.JSONB, nullable=False),
        sa.Column("content_hash", sa.Text, nullable=False),
        sa.Column("source_url", sa.Text, nullable=False),
        sa.Column("fetch_url", sa.Text, nullable=False),
        # SPDX id (or UNKNOWN when the OSV data page states no license for the upstream DB)
        sa.Column("license", sa.Text, nullable=False),
        sa.Column("collected_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("first_seen_at", TS, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("osv_id", "export_ecosystem"),
        schema="raw",
    )
    op.create_index("ix_osv_modified", "osv_vulnerability", ["modified"], schema="raw")
    op.create_index(
        "ix_osv_products", "osv_vulnerability", ["matched_products"],
        schema="raw", postgresql_using="gin",
    )
    op.create_table(
        "web_page",
        sa.Column("url", sa.Text, primary_key=True),
        sa.Column("source_id", sa.Text, nullable=False),
        sa.Column("http_status", sa.Integer, nullable=False),
        sa.Column("content_type", sa.Text),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("content_hash", sa.Text, nullable=False),
        sa.Column("etag", sa.Text),
        sa.Column("last_modified", sa.Text),
        sa.Column("source_url", sa.Text, nullable=False),
        sa.Column("license", sa.Text, nullable=False),
        # time the stored content last changed (unchanged re-fetches do not touch the row)
        sa.Column("collected_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("first_seen_at", TS, nullable=False, server_default=sa.func.now()),
        schema="raw",
    )


def downgrade() -> None:
    for t in ("web_page", "osv_vulnerability", "collection_state", "collection_run"):
        op.drop_table(t, schema="raw")
