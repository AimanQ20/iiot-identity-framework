"""Shared revocation boundary: Member 1 owns device; Member 2 owns token revocation."""

from sqlalchemy.orm import Session

from fog.models import Device, RevokedDevice, RevokedToken


def revoke_device_placeholder(did: str, reason: str, db: Session) -> dict:
    """Immediately and persistently revoke a device by DID.

    Both Phase 2 (`process_temporary_access`) and Phase 3
    (`process_permanent_access`) check `RevokedDevice` on every request, so a
    revoked device is rejected even with an otherwise-valid, unexpired token
    or a structurally valid Merkle inclusion proof -- this is what lets the
    demo show the difference between an old historical proof and current
    authorization status.
    """
    existing = db.get(RevokedDevice, did)
    if existing is None:
        db.add(RevokedDevice(did=did, reason=reason))
        db.query(Device).filter_by(did=did).update({"status": "REVOKED"})
        db.commit()
        status = "REVOKED"
    else:
        status = "ALREADY_REVOKED"
        reason = existing.reason
    return {"did": did, "reason": reason, "status": status}


def revoke_token_placeholder(jti: str, reason: str, db: Session) -> dict:
    """Immediately and persistently revoke a temporary token by its jti.

    Once recorded, `validate_temporary_token` rejects this jti even though
    its signature and expiry are still otherwise individually valid. The
    caller (fog API) only has the jti, not the original token, so the owning
    DID isn't tracked here -- attack demos can cross-check it against the
    `/token/issue` response logged at issuance time.
    """
    existing = db.get(RevokedToken, jti)
    if existing is not None:
        return {"jti": jti, "reason": existing.reason, "status": "ALREADY_REVOKED"}

    db.add(RevokedToken(jti=jti, did="unknown", reason=reason))
    db.commit()
    return {"jti": jti, "reason": reason, "status": "REVOKED"}
