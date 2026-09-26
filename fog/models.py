from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from fog.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    did: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    public_key: Mapped[str] = mapped_column(Text)
    public_key_thumbprint: Mapped[str] = mapped_column(String(64), index=True)
    device_type: Mapped[str] = mapped_column(String(50))
    role: Mapped[str] = mapped_column(String(50))
    zone: Mapped[str] = mapped_column(String(50), default="zone-1")
    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    authentication_complete: Mapped[bool] = mapped_column(Boolean, default=False)
    pop_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Epoch(Base):
    __tablename__ = "epochs"

    epoch_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merkle_root: Mapped[str] = mapped_column(String(64))
    device_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class DeviceProof(Base):
    __tablename__ = "device_proofs"
    __table_args__ = (UniqueConstraint("did", "epoch_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    did: Mapped[str] = mapped_column(String(200), index=True)
    epoch_id: Mapped[int] = mapped_column(Integer, index=True)
    leaf: Mapped[str] = mapped_column(String(64))
    proof_json: Mapped[str] = mapped_column(Text)


class UsedNonce(Base):
    __tablename__ = "used_nonces"
    __table_args__ = (UniqueConstraint("did", "nonce"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    did: Mapped[str] = mapped_column(String(200), index=True)
    nonce: Mapped[str] = mapped_column(String(200))
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class RevokedDevice(Base):
    __tablename__ = "revoked_devices"

    did: Mapped[str] = mapped_column(String(200), primary_key=True)
    reason: Mapped[str] = mapped_column(String(500))
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(100), primary_key=True)
    did: Mapped[str] = mapped_column(String(200), index=True)
    reason: Mapped[str] = mapped_column(String(500))
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

