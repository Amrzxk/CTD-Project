"""SQLAlchemy ORM models for the persistence floor.

Four tables:

* ``users`` — authentication identities (admin / analyst).
* ``predictions`` — the analyst-facing queue. Source of truth for the API.
* ``ack_history`` — append-only audit trail; one row per ack-state change.
* ``suppressions`` — server-enforced suppression rules.

Design notes:

* Predictions keep their legacy ``id`` string shape (``batch_<uuid>_<i>`` /
  ``manual_<uuid>``) so existing API responses don't change shape.
* ``flow_timestamp`` is the original event time (was ``timestamp`` in the
  old in-memory dict); ``first_seen_at`` is the DB insert time. Their
  difference is the *detection latency* (MTTD).
* Heavy ML payloads (``stage2_probs``, ``stage3_probs``, ``ml_features``,
  ``mitre``) live in ``JSONB`` columns. Indexable if we ever need to query
  inside them; today we only read/write them whole.
* All timestamps are ``TIMESTAMPTZ`` with ``server_default=NOW()`` where
  applicable so the DB owns clock truth.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class User(Base):
    """Authenticated identity. Username is normalised to lowercase at the
    application layer (in `app/db/repositories/users.py`) so we avoid
    depending on the Postgres ``citext`` extension."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    # True for analyst accounts that were just created (or admin-reset) with a
    # temporary password. The dashboard forces a change-password step on first
    # login and clears this flag once the user picks their own password. See
    # app/api/auth.py (change_password) and the admin user-management router.
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # Bumped to invalidate every outstanding session token for this user at
    # once (password change, "log out everywhere"). The value is embedded in
    # the JWT at mint time and compared on every request — a mismatch is a
    # hard 401. See app/auth/dependencies.py.
    token_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("username", name="uq_users_username"),
        CheckConstraint("role IN ('admin', 'analyst')", name="role_valid"),
    )


class UserAdminHistory(Base):
    """Append-only audit trail for admin account-management actions.

    One row per privileged action an admin takes against another account
    (create / enable / disable / reset_password). Mirrors the ``ack_history``
    pattern: ``target_username`` is denormalised so the trail survives even
    if the target row is later deleted (the FKs are ``SET NULL``).
    """

    __tablename__ = "user_admin_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    actor_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="SET NULL")
    )
    target_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="SET NULL")
    )
    target_username: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "action IN ('create', 'enable', 'disable', 'reset_password')",
            name="user_admin_action_valid",
        ),
        Index("ix_user_admin_history_target", "target_id", "created_at"),
    )


class Prediction(Base):
    """Per-flow prediction record. Mirrors the shape returned by
    ``_format_predictions()`` so the API can serialise straight off the
    SQLA row with no extra translation."""

    __tablename__ = "predictions"

    # Keep the legacy string id shape so URL paths and external references
    # (incident reports, CSV exports) remain stable.
    id: Mapped[str] = mapped_column(String(128), primary_key=True)

    flow_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    # DB-side insert time. Enables real MTTD (= first_seen_at - flow_timestamp).
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="N/A")
    packet_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Model-derived label fields.
    prediction: Mapped[str] = mapped_column(String(16), nullable=False, default="Normal")
    # Text rather than VARCHAR — when the verdict is confirmed/signature_only,
    # this column holds the Snort rule msg which can run 100+ chars
    # (ETOpen signatures in particular have long descriptive messages).
    attack_type: Mapped[str | None] = mapped_column(Text)
    family: Mapped[str | None] = mapped_column(String(64), index=True)
    # subtype mirrors attack_type for signature_only verdicts where it
    # carries the Snort rule msg — needs the same TEXT room as attack_type.
    subtype: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    severity: Mapped[str | None] = mapped_column(String(16))

    stage1_p: Mapped[float | None] = mapped_column(Float)
    stage2_p: Mapped[float | None] = mapped_column(Float)
    stage3_p: Mapped[float | None] = mapped_column(Float)
    # Probability vectors are short dicts; storing as JSONB keeps the row
    # tidy and avoids a fan-out table we'd never query into individually.
    stage2_probs: Mapped[dict | None] = mapped_column(JSONB)
    stage3_probs: Mapped[dict | None] = mapped_column(JSONB)
    ml_features: Mapped[dict | None] = mapped_column(JSONB)
    mitre: Mapped[dict | None] = mapped_column(JSONB)

    # Hybrid verdict cell + provenance.
    source: Mapped[str | None] = mapped_column(String(32), index=True)
    model_version: Mapped[str | None] = mapped_column(String(64))

    # Snort signature metadata (only populated when source is confirmed /
    # signature_only).
    snort_msg: Mapped[str | None] = mapped_column(Text)
    snort_sid: Mapped[int | None] = mapped_column(Integer)
    snort_classtype: Mapped[str | None] = mapped_column(String(64))
    snort_priority: Mapped[int | None] = mapped_column(Integer)

    # Analyst workflow. The latest ack state mirrors onto the row for
    # cheap reads; the full history lives in `ack_history`.
    ack_state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="new", server_default="new", index=True
    )
    ack_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ack_note: Mapped[str | None] = mapped_column(Text)
    ack_by: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint(
            "ack_state IN ('new', 'reviewed', 'escalated', 'dismissed')",
            name="ack_state_valid",
        ),
        # Composite index for the campaign-grouping query
        # (GROUP BY source_ip, destination_ip, family).
        Index("ix_predictions_campaign", "source_ip", "destination_ip", "family"),
    )


class AckHistory(Base):
    """Append-only audit trail. One row per ack-state change.

    Read-side: when the drawer opens for a prediction, we surface this
    table so the analyst can see who flipped what and when. Write-side:
    bumped from `predictions.repositories.ack(...)` inside the same
    transaction that updates `Prediction.ack_state`.
    """

    __tablename__ = "ack_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    prediction_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("predictions.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="SET NULL")
    )
    from_state: Mapped[str] = mapped_column(String(16), nullable=False)
    to_state: Mapped[str] = mapped_column(String(16), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_ack_history_pred_changed", "prediction_id", "changed_at"),
    )


class Suppression(Base):
    """Server-enforced suppression rule. Matched future flows are dropped
    *before* they reach `predictions`, not just hidden in the UI.

    `kind` constrains how `value` is interpreted:

    * ``sid``       → exact Snort SID match.
    * ``src_ip``    → exact source IP match.
    * ``src_cidr``  → source IP inside this CIDR network.
    * ``flow_key``  → exact canonical "ip:port-ip:port-PROTO" match.
    """

    __tablename__ = "suppressions"

    # Keep the existing `supp_<uuid>` shape so log lines remain stable.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(256), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    note: Mapped[str | None] = mapped_column(Text)
    # Bumped every time `match()` returns this rule. Visible in the UI so
    # an analyst can tell whether a rule is actually firing.
    hits: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_by: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint(
            "kind IN ('sid', 'src_ip', 'src_cidr', 'flow_key')",
            name="kind_valid",
        ),
    )
