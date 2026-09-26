"""MEMBER 2: Phase 2 temporary-token issuance and validation."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt

from fog.schemas import AuthenticatedDevice
from fog.settings import settings


def issue_temporary_token(device: AuthenticatedDevice) -> tuple[str, int]:
    """Working baseline; Member 2 extends validation and policy checks."""
    if not device.authentication_complete or not device.proof_of_possession_verified:
        raise ValueError("Unauthenticated devices cannot receive tokens")
    now = datetime.now(timezone.utc)
    payload = {
        "jti": str(uuid4()),
        "sub": device.did,
        "pk_thumbprint": device.public_key_thumbprint,
        "device_type": device.device_type.value,
        "role": device.role,
        "status": "provisional",
        "iat": now,
        "exp": now + timedelta(seconds=settings.token_ttl_seconds),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, settings.token_ttl_seconds


def validate_temporary_token(token: str) -> dict:
    """TODO MEMBER 2: additionally check token and device revocation."""
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])

