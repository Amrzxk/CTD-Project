"""Widen predictions.attack_type to TEXT.

When the verdict is `confirmed` or `signature_only`, attack_type holds
the Snort rule msg, which can be 100+ chars (ETOpen rules in particular
have long descriptive messages, e.g. "ET WEB_SERVER Unusually Fast HTTP
Requests With Referer Url Matching DoS Tool"). The original VARCHAR(64)
overflows and the whole batch insert rolls back.

Revision ID: 0002_widen_attack_type
Revises: 0001_initial
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0002_widen_attack_type"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "predictions",
        "attack_type",
        existing_type=sa.String(length=64),
        type_=sa.Text(),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "predictions",
        "attack_type",
        existing_type=sa.Text(),
        type_=sa.String(length=64),
        existing_nullable=True,
    )
