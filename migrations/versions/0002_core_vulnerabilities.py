"""core: normalized vulnerabilities (OSV) and PostgreSQL advisories

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "vulnerability",
        sa.Column("osv_id", sa.Text, primary_key=True),
        sa.Column("aliases", pg.ARRAY(sa.Text), nullable=False),
        sa.Column("summary", sa.Text),
        sa.Column("details", sa.Text),
        sa.Column("severity_vector", sa.Text),
        sa.Column("severity_score", sa.Numeric(3, 1)),
        # LOW / MEDIUM / HIGH / CRITICAL; NULL when the record carries no severity at all
        sa.Column("severity_label", sa.Text),
        # cvss3_computed | cvss_vector_only | database_specific | NULL
        sa.Column("severity_source", sa.Text),
        sa.Column("published", TS),
        sa.Column("modified", TS, nullable=False),
        sa.Column("withdrawn", TS),
        sa.Column("export_ecosystems", pg.ARRAY(sa.Text), nullable=False),
        sa.Column("matched_products", pg.ARRAY(sa.Text), nullable=False),
        sa.Column("license", sa.Text, nullable=False),
        sa.Column("publishable", sa.Boolean, nullable=False),
        sa.Column("source_url", sa.Text, nullable=False),
        # hash of the raw rows this row was built from: unchanged raw -> nothing to redo
        sa.Column("raw_hash", sa.Text, nullable=False),
        sa.Column("normalized_at", TS, nullable=False, server_default=sa.func.now()),
        schema="core",
    )
    op.create_table(
        "affected_package",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("osv_id", sa.Text, sa.ForeignKey("core.vulnerability.osv_id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("ordinal", sa.Integer, nullable=False),
        sa.Column("ecosystem", sa.Text),           # as given, e.g. Debian:12
        sa.Column("ecosystem_base", sa.Text),      # Debian
        sa.Column("package", sa.Text),
        sa.Column("purl", sa.Text),
        sa.Column("versions", pg.ARRAY(sa.Text), nullable=False),  # explicit version list
        sa.UniqueConstraint("osv_id", "ordinal"),
        schema="core",
    )
    op.create_index("ix_affected_package_name", "affected_package", ["ecosystem_base", "package"],
                    schema="core")
    op.create_table(
        "version_range",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("affected_id", sa.BigInteger,
                  sa.ForeignKey("core.affected_package.id", ondelete="CASCADE"), nullable=False),
        sa.Column("range_type", sa.Text, nullable=False),  # ECOSYSTEM | SEMVER | GIT
        sa.Column("repo", sa.Text),                          # GIT ranges
        sa.Column("introduced", sa.Text),                    # "0" = from the beginning
        sa.Column("fixed", sa.Text),
        sa.Column("last_affected", sa.Text),
        sa.Column("limit_", sa.Text),
        schema="core",
    )
    op.create_index("ix_version_range_affected", "version_range", ["affected_id"], schema="core")
    op.create_table(
        "vuln_reference",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("osv_id", sa.Text, sa.ForeignKey("core.vulnerability.osv_id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("ref_type", sa.Text),
        sa.Column("url", sa.Text, nullable=False),
        schema="core",
    )
    op.create_index("ix_vuln_reference_osv", "vuln_reference", ["osv_id"], schema="core")
    op.create_table(
        "pg_advisory",
        sa.Column("cve_id", sa.Text, primary_key=True),
        sa.Column("title", sa.Text),
        sa.Column("description", sa.Text),         # verbatim text of the page
        sa.Column("component", sa.Text),
        sa.Column("affected_text", sa.Text),       # verbatim
        sa.Column("fixed_text", sa.Text),          # verbatim
        sa.Column("fixed_versions", pg.ARRAY(sa.Text), nullable=False),
        sa.Column("cvss_vector", sa.Text),
        sa.Column("cvss_score", sa.Numeric(3, 1)),
        sa.Column("cvss_score_source", sa.Text),   # page | computed | NULL
        sa.Column("full_text", sa.Text, nullable=False),
        # which fields the parser found, e.g. {"title": true, "affected": false}
        sa.Column("parse_flags", pg.JSONB, nullable=False),
        sa.Column("license", sa.Text, nullable=False),
        sa.Column("publishable", sa.Boolean, nullable=False),
        sa.Column("source_url", sa.Text, nullable=False),
        sa.Column("raw_hash", sa.Text, nullable=False),
        sa.Column("normalized_at", TS, nullable=False, server_default=sa.func.now()),
        schema="core",
    )


def downgrade() -> None:
    for t in ("pg_advisory", "vuln_reference", "version_range", "affected_package",
              "vulnerability"):
        op.drop_table(t, schema="core")
