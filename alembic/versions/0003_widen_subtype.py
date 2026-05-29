"""Widen predictions.subtype to TEXT.

Same reasoning as 0002: the signature_only verdict copies the Snort
rule msg into both attack_type and subtype (see
``_apply_hybrid_overrides`` in app/api/routes.py), so subtype needs the
same TEXT room or the batch insert hits the same truncation error.

Revision ID: 0003_widen_subtype
Revises: 0002_widen_attack_type
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0003_widen_subtype"
down_revision: Union[str, None] = "0002_widen_attack_type"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "predictions",
        "subtype",
        existing_type=sa.String(length=64),
        type_=sa.Text(),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "predictions",
        "subtype",
        existing_type=sa.Text(),
        type_=sa.String(length=64),
        existing_nullable=True,
    )
