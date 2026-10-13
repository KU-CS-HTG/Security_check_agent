"""core.pg_advisory_version: per-major-version fix table of a PostgreSQL advisory

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("pg_advisory", sa.Column("cvss_version", sa.Text), schema="core")
    op.create_table(
        "pg_advisory_version",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.Text, sa.ForeignKey("core.pg_advisory.cve_id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("ordinal", sa.Integer, nullable=False),
        sa.Column("affected_major", sa.Text, nullable=False),   # "14"
        sa.Column("fixed_in", sa.Text),                         # "14.3" (NULL: not fixed)
        sa.Column("fix_published", sa.Date),
        sa.UniqueConstraint("cve_id", "ordinal"),
        schema="core",
    )
    op.create_index("ix_pg_advisory_version_cve", "pg_advisory_version", ["cve_id"], schema="core")


def downgrade() -> None:
    op.drop_table("pg_advisory_version", schema="core")
    op.drop_column("pg_advisory", "cvss_version", schema="core")
