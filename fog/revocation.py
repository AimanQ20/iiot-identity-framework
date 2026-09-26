"""Device and token revocation.

Member 1 owns device revocation.
Member 2 owns token revocation.
"""

from sqlalchemy.orm import Session

from fog.models import Device, RevokedDevice, RevokedToken


def revoke_device(
    did: str,
    reason: str,
    db: Session,
) -> dict:
    """Immediately revoke a registered device."""

    device = db.query(Device).filter(
        Device.did == did
    ).first()

    if device is None:
        raise ValueError("Device does not exist")

    existing_revocation = db.query(RevokedDevice).filter(
        RevokedDevice.did == did
    ).first()

    if existing_revocation is not None:
        return {
            "success": True,
            "code": "DEVICE_ALREADY_REVOKED",
            "did": did,
            "reason": existing_revocation.reason,
        }

    device.status = "REVOKED"

    revocation = RevokedDevice(
        did=did,
        reason=reason,
    )

    db.add(revocation)
    db.commit()

    return {
        "success": True,
        "code": "DEVICE_REVOKED",
        "did": did,
        "reason": reason,
        "message": (
            "Device revoked immediately. Historical epoch "
            "proofs remain stored but no longer grant access."
        ),
    }


def is_device_revoked(
    did: str,
    db: Session,
) -> bool:
    """Check current device-revocation status."""

    return (
        db.query(RevokedDevice)
        .filter(RevokedDevice.did == did)
        .first()
        is not None
    )


def revoke_token(
    jti: str,
    did: str,
    reason: str,
    db: Session,
) -> dict:
    """MEMBER 2: immediately revoke a temporary token."""

    existing = db.query(RevokedToken).filter(
        RevokedToken.jti == jti
    ).first()

    if existing is not None:
        return {
            "success": True,
            "code": "TOKEN_ALREADY_REVOKED",
            "jti": jti,
        }

    db.add(
        RevokedToken(
            jti=jti,
            did=did,
            reason=reason,
        )
    )

    db.commit()

    return {
        "success": True,
        "code": "TOKEN_REVOKED",
        "jti": jti,
        "did": did,
    }