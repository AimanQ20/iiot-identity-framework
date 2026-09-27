"""Shared revocation boundary: Member 1 owns device; Member 2 owns token revocation."""

from sqlalchemy.orm import Session

from fog.models import RevokedToken


def revoke_device_placeholder(did: str, reason: str) -> dict:
    """TODO MEMBER 1: persist device revocation and update status."""
    return {"did": did, "reason": reason, "status": "NOT_IMPLEMENTED"}


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
