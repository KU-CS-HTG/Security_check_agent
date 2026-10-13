"""core.document and core.clause (parsed documentation, split into clauses)

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "document",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("url", sa.Text, nullable=False, unique=True),
        sa.Column("source_id", sa.Text, nullable=False),
        sa.Column("title", sa.Text),
        sa.Column("version", sa.Text),
        sa.Column("format", sa.Text, nullable=False),         # html | pdf
        sa.Column("license", sa.Text, nullable=False),        # SPDX id or KOGL type
        sa.Column("kogl_type", sa.Integer),
        sa.Column("copyright_notice", sa.Text),               # kept with every copy (license term)
        sa.Column("publishable", sa.Boolean, nullable=False),
        sa.Column("raw_hash", sa.Text, nullable=False),       # raw content hash + parser version
        sa.Column("fetched_at", TS),
        sa.Column("parsed_at", TS, nullable=False, server_default=sa.func.now()),
        schema="core",
    )
    op.create_table(
        "clause",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("document_id", sa.BigInteger,
                  sa.ForeignKey("core.document.id", ondelete="CASCADE"), nullable=False),
        # stable identity inside a document (heading anchor, or heading path), so a rebuild keeps
        # the id of an unchanged clause and results attached to it (extractions) survive
        sa.Column("key", sa.Text, nullable=False),
        sa.Column("ordinal", sa.Integer, nullable=False),
        sa.Column("heading_path", pg.ARRAY(sa.Text), nullable=False),
        sa.Column("text", sa.Text, nullable=False),           # source text, whitespace normalised
        sa.Column("text_hash", sa.Text, nullable=False),
        sa.Column("source_url", sa.Text, nullable=False),     # page url + #anchor when known
        sa.UniqueConstraint("document_id", "key"),
        schema="core",
    )
    op.create_index("ix_clause_document", "clause", ["document_id", "ordinal"], schema="core")


def downgrade() -> None:
    op.drop_table("clause", schema="core")
    op.drop_table("document", schema="core")
