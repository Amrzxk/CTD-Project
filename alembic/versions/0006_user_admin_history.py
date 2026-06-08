"""Add user_admin_history audit table.

One append-only row per admin account-management action (create / enable /
disable / reset_password). ``target_username`` is denormalised so the trail
survives a later delete of the target row (both FKs are ``SET NULL``).
Mirrors the ``ack_history`` design.

Revision ID: 0006_user_admin_history
Revises: 0005_user_must_change_password
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0006_user_admin_history"
down_revision: Union[str, None] = "0005_user_must_change_password"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_admin_history",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("actor_id", sa.BigInteger(), nullable=True),
        sa.Column("target_id", sa.BigInteger(), nullable=True),
        sa.Column("target_username", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_admin_history"),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"],
            name="fk_user_admin_history_actor_id_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["target_id"], ["users.id"],
            name="fk_user_admin_history_target_id_users",
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "action IN ('create', 'enable', 'disable', 'reset_password')",
            name="ck_user_admin_history_user_admin_action_valid",
        ),
    )
    op.create_index(
        "ix_user_admin_history_target",
        "user_admin_history",
        ["target_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_user_admin_history_target", table_name="user_admin_history")
    op.drop_table("user_admin_history")
