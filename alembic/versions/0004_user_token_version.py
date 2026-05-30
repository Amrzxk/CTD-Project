"""Add users.token_version for session revocation.

Bumping ``token_version`` invalidates every outstanding JWT for a user at
once (password change / "log out everywhere"). The value is embedded in the
session token at mint time and compared on every request — see
``app/auth/dependencies.py``. Defaults to 0 so existing rows and tokens
(which carry an implicit version 0) keep working across the deploy.

Revision ID: 0004_user_token_version
Revises: 0003_widen_subtype
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0004_user_token_version"
down_revision: Union[str, None] = "0003_widen_subtype"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "token_version",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "token_version")
