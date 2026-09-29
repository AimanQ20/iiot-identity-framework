"""Device and temporary-token revocation services."""

from sqlalchemy.orm import Session

from fog.models import Device, RevokedDevice, RevokedToken


def revoke_device(
    did: str,
    reason: str,
    db: Session,
) -> dict:
    """Immediately and persistently revoke a registered device.

    Historical proofs and epoch roots are preserved, but all current
    temporary and permanent resource requests are denied.
    """

    device = (
        db.query(Device)
        .filter(Device.did == did)
        .first()
    )

    if device is None:
        raise ValueError("Device does not exist")

    existing_revocation = db.get(
        RevokedDevice,
        did,
    )

    if existing_revocation is not None:
        return {
            "success": True,
            "code": "DEVICE_ALREADY_REVOKED",
            "status": "ALREADY_REVOKED",
            "did": did,
            "reason": existing_revocation.reason,
            "message": "Device was already revoked",
        }

    device.status = "REVOKED"

    db.add(
        RevokedDevice(
            did=did,
            reason=reason,
        )
    )

    db.commit()

    return {
        "success": True,
        "code": "DEVICE_REVOKED",
        "status": "REVOKED",
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
    """Return True when the DID is in the device revocation registry."""

    return (
        db.get(RevokedDevice, did)
        is not None
    )


def revoke_token(
    jti: str,
    reason: str,
    db: Session,
    did: str = "unknown",
) -> dict:
    """Immediately and persistently revoke a temporary token."""

    existing_revocation = db.get(
        RevokedToken,
        jti,
    )

    if existing_revocation is not None:
        return {
            "success": True,
            "code": "TOKEN_ALREADY_REVOKED",
            "status": "ALREADY_REVOKED",
            "jti": jti,
            "did": existing_revocation.did,
            "reason": existing_revocation.reason,
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
        "status": "REVOKED",
        "jti": jti,
        "did": did,
        "reason": reason,
        "message": "Temporary token revoked immediately",
    }