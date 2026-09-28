"""MEMBER 2: Phase 2 temporary-token issuance and validation."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
from sqlalchemy.orm import Session

from fog.authorization import load_policies
from fog.models import BatchQueue, Device, RevokedDevice, RevokedToken
from fog.schemas import AuthenticatedDevice
from fog.settings import settings


class TokenValidationError(Exception):
    """Base class for temporary-token validation failures."""

    code = "TOKEN_INVALID"


class TokenExpiredError(TokenValidationError):
    code = "TOKEN_EXPIRED"


class TokenInvalidError(TokenValidationError):
    code = "TOKEN_INVALID"


class TokenRevokedError(TokenValidationError):
    code = "TOKEN_REVOKED"


class DeviceRevokedError(TokenValidationError):
    code = "DEVICE_REVOKED"


def _provisional_actions(device_type: str) -> list[str]:
    """Collect every operation the provisional policy grants this device type,
    across all of its provisional resources, for inclusion as a token claim."""
    rules = load_policies().get("provisional", {}).get(device_type, {})
    actions: set[str] = set()
    for allowed_ops in rules.values():
        actions.update(op.upper() for op in allowed_ops)
    return sorted(actions)


def issue_temporary_token(device: AuthenticatedDevice, db: Session) -> tuple[str, int]:
    """Issue a short-lived, fog-signed provisional token and queue the device
    for the next/finalized registration batch (Phase 2 bridging mechanism)."""
    if not device.authentication_complete or not device.proof_of_possession_verified:
        raise ValueError("Unauthenticated devices cannot receive tokens")

    if db.get(RevokedDevice, device.did) is not None:
        raise ValueError("Device is revoked and cannot receive a temporary token")

    now = datetime.now(timezone.utc)
    payload = {
        "jti": str(uuid4()),
        "sub": device.did,
        "pk_thumbprint": device.public_key_thumbprint,
        "device_type": device.device_type.value,
        "role": device.role,
        "status": "provisional",
        "permitted_actions": _provisional_actions(device.device_type.value),
        "iat": now,
        "exp": now + timedelta(seconds=settings.token_ttl_seconds),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

    _upsert_device_record(db, device)
    _queue_for_batch(db, device)

    return token, settings.token_ttl_seconds


def _upsert_device_record(db: Session, device: AuthenticatedDevice) -> None:
    """Keep a local record of the device's DID/public key so later requests can
    be bound back to the exact key that was authenticated (device/token binding)."""
    existing = db.query(Device).filter_by(did=device.did).one_or_none()
    if existing is None:
        db.add(
            Device(
                device_id=device.device_id,
                did=device.did,
                public_key=device.public_key,
                public_key_thumbprint=device.public_key_thumbprint,
                device_type=device.device_type.value,
                role=device.role,
                zone=device.zone,
                status="PENDING",
                authentication_complete=True,
                pop_verified=True,
            )
        )
        db.commit()


def _queue_for_batch(db: Session, device: AuthenticatedDevice) -> None:
    """Queue the device for inclusion in the next/finalized batch. Member 1's
    batch-finalization step should mark the row `included=True` once the
    device's leaf is folded into a finalized epoch tree."""
    already_queued = (
        db.query(BatchQueue).filter_by(did=device.did, included=False).one_or_none()
    )
    if already_queued is None:
        db.add(
            BatchQueue(
                did=device.did,
                device_type=device.device_type.value,
                role=device.role,
            )
        )
        db.commit()


def validate_temporary_token(token: str, db: Session) -> dict:
    """Check token signature and expiry, then token- and device-revocation status."""
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpiredError("Temporary token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenInvalidError(f"Temporary token is malformed or has an invalid signature: {exc}") from exc

    if db.get(RevokedToken, payload["jti"]) is not None:
        raise TokenRevokedError("Temporary token has been revoked")

    if db.get(RevokedDevice, payload["sub"]) is not None:
        raise DeviceRevokedError("Device holding this token has been revoked")

    return payload
