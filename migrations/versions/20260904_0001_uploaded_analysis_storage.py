"""Create uploaded analysis and finding storage."""
from alembic import op
import sqlalchemy as sa

revision = "20260904_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("analysis_id", sa.String(length=64), primary_key=True),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("packet_count", sa.Integer(), nullable=False),
        sa.Column("window_count", sa.Integer(), nullable=False),
        sa.Column("duration_seconds", sa.Integer(), nullable=False),
        sa.Column("protocols", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("error_message", sa.String(length=1000)),
    )
    op.create_table(
        "findings",
        sa.Column("finding_id", sa.String(length=128), nullable=False),
        sa.Column("analysis_id", sa.String(length=64), sa.ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", sa.String(length=128)),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("observed_metric", sa.JSON()),
        sa.Column("threshold", sa.JSON()),
        sa.Column("explanation", sa.JSON(), nullable=False),
        sa.Column("recommendation", sa.String(length=2000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("analysis_id", "finding_id"),
    )
    op.create_index("ix_findings_analysis_id", "findings", ["analysis_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])


def downgrade() -> None:
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_analysis_id", table_name="findings")
    op.drop_table("findings")
    op.drop_table("analyses")