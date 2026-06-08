"""Add users.must_change_password for forced first-login change.

Analyst accounts created (or admin-reset) with a temporary password carry
``must_change_password=True``; the dashboard forces a change-password step on
first login and clears the flag once the user picks their own password. The
bootstrap admin and all existing rows default to ``False`` so the deploy is a
no-op for them.

Revision ID: 0005_user_must_change_password
Revises: 0004_user_token_version
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0005_user_must_change_password"
down_revision: Union[str, None] = "0004_user_token_version"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "must_change_password")
