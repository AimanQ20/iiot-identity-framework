"""Shared revocation boundary: Member 1 owns device; Member 2 owns token revocation."""


def revoke_device_placeholder(did: str, reason: str) -> dict:
    """TODO MEMBER 1: persist device revocation and update status."""
    return {"did": did, "reason": reason, "status": "NOT_IMPLEMENTED"}


def revoke_token_placeholder(jti: str, reason: str) -> dict:
    """TODO MEMBER 2: persist immediate token revocation."""
    return {"jti": jti, "reason": reason, "status": "NOT_IMPLEMENTED"}

