"""core: extraction runs, per-clause results, extracted check items (reviewable)

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "extraction_run",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("started_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", TS),
        sa.Column("status", sa.Text, nullable=False, server_default="running"),
        sa.Column("model", sa.Text, nullable=False),
        sa.Column("prompt_version", sa.Text, nullable=False),
        sa.Column("schema_version", sa.Text, nullable=False),
        sa.Column("params", pg.JSONB),
        sa.Column("stats", pg.JSONB),
        schema="core",
    )
    op.create_table(
        "extraction_result",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.BigInteger,
                  sa.ForeignKey("core.extraction_run.id", ondelete="SET NULL")),
        sa.Column("clause_id", sa.BigInteger,
                  sa.ForeignKey("core.clause.id", ondelete="CASCADE"), nullable=False),
        # the clause text this result was made from: a changed clause makes the result stale
        sa.Column("text_hash", sa.Text, nullable=False),
        sa.Column("model", sa.Text, nullable=False),
        sa.Column("prompt_version", sa.Text, nullable=False),
        sa.Column("schema_version", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),         # ok | empty | failed
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("error", sa.Text),
        sa.Column("raw_response", sa.Text),                   # last model output, for audit
        sa.Column("prompt_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('ok', 'empty', 'failed')", name="ck_result_status"),
        sa.UniqueConstraint("clause_id", "text_hash", "model", "prompt_version",
                            name="uq_extraction_result"),
        schema="core",
    )
    op.create_table(
        "extracted_item",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("result_id", sa.BigInteger,
                  sa.ForeignKey("core.extraction_result.id", ondelete="CASCADE"), nullable=False),
        sa.Column("clause_id", sa.BigInteger,
                  sa.ForeignKey("core.clause.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_type", sa.Text, nullable=False, server_default="check_item"),
        sa.Column("payload", pg.JSONB, nullable=False),      # the item exactly as validated
        sa.Column("evidence_quote", sa.Text, nullable=False),
        sa.Column("evidence_match", sa.Text),                # exact | loose | NULL (not found)
        sa.Column("remediation_match", sa.Text),
        sa.Column("target_found", sa.Boolean, nullable=False),
        sa.Column("evidence_verified", sa.Boolean, nullable=False),
        # pending (verified, awaiting review) | approved | rejected (by a person or automatically)
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("risk_source", sa.Text),                   # document | NULL
        sa.Column("review_note", sa.Text),
        sa.Column("reviewed_at", TS),
        sa.CheckConstraint("status IN ('pending', 'approved', 'rejected')", name="ck_item_status"),
        schema="core",
    )
    op.create_index("ix_extracted_item_clause", "extracted_item", ["clause_id"], schema="core")
    op.create_index("ix_extracted_item_status", "extracted_item", ["status"], schema="core")


def downgrade() -> None:
    for t in ("extracted_item", "extraction_result", "extraction_run"):
        op.drop_table(t, schema="core")
