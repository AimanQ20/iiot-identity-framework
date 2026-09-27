"""MEMBER 2 leads request validation; Member 1 supplies permanent proof verification."""

import base64
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from fog.authorization import authorize
from fog.models import Device, UsedNonce
from fog.registration import public_key_thumbprint
from fog.schemas import DecisionResponse, PermanentAccessRequest, TemporaryAccessRequest
from fog.token_service import (
    DeviceRevokedError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
    validate_temporary_token,
)

# How far a request's client-supplied timestamp may drift from fog time before
# it is treated as stale/replayed rather than a fresh request.
NONCE_FRESHNESS_SECONDS = 60


def _canonical_message(
    did: str, resource: str, operation: str, body_hash: str, nonce: str, timestamp: int, token_jti: str
) -> bytes:
    """Canonical signed resource request, per docs/CONTRACTS.md."""
    return f"{did}|{resource}|{operation}|{body_hash}|{nonce}|{timestamp}|{token_jti}".encode("utf-8")


def _deny(code: str, message: str) -> DecisionResponse:
    return DecisionResponse(success=False, code=code, message=message, decision="DENY")


def process_temporary_access(request: TemporaryAccessRequest, db: Session) -> DecisionResponse:
    """Phase 2 provisional-access pipeline.

    Order of checks: token signature/expiry -> token/device revocation ->
    device/token binding -> timestamp freshness -> fresh-nonce enforcement ->
    request proof-of-possession (device/token binding) -> provisional policy.
    """
    try:
        payload = validate_temporary_token(request.token, db)
    except TokenExpiredError as exc:
        return _deny("TOKEN_EXPIRED", str(exc))
    except TokenRevokedError as exc:
        return _deny("TOKEN_REVOKED", str(exc))
    except DeviceRevokedError as exc:
        return _deny("DEVICE_REVOKED", str(exc))
    except TokenInvalidError as exc:
        return _deny("TOKEN_INVALID", str(exc))

    # Device/token binding: the token must have been issued to the DID making
    # this request, not merely be a valid token copied from somewhere else.
    if payload["sub"] != request.did:
        return _deny("TOKEN_BINDING_FAILED", "Token subject does not match the requesting DID")

    device = db.query(Device).filter_by(did=request.did).one_or_none()
    if device is None:
        return _deny("TOKEN_BINDING_FAILED", "No registered device record for this DID")

    if payload.get("pk_thumbprint") != public_key_thumbprint(device.public_key):
        return _deny(
            "TOKEN_BINDING_FAILED",
            "Token key fingerprint does not match the device's registered public key",
        )

    now = int(time.time())
    if abs(now - request.timestamp) > NONCE_FRESHNESS_SECONDS:
        return _deny("STALE_TIMESTAMP", "Request timestamp is outside the freshness window")

    # Fresh-nonce enforcement: a (did, nonce) pair may be used exactly once.
    # Recorded before signature verification so a captured-and-resent request
    # can never be replayed regardless of how the first attempt resolved.
    try:
        db.add(UsedNonce(did=request.did, nonce=request.nonce))
        db.commit()
    except IntegrityError:
        db.rollback()
        return _deny("NONCE_REUSED", "This nonce has already been used for this device")

    # Request proof-of-possession: a stolen token alone is not enough. The
    # request itself must be signed, fresh, by the device's private key.
    message = _canonical_message(
        request.did,
        request.resource,
        request.operation,
        request.body_hash,
        request.nonce,
        request.timestamp,
        payload["jti"],
    )
    try:
        public_key = serialization.load_pem_public_key(device.public_key.encode("utf-8"))
        signature = base64.b64decode(request.signature)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return _deny("REQUEST_SIGNATURE_INVALID", "Request signature does not match the device's key")

    permitted_actions = set(payload.get("permitted_actions", []))
    policy_allows = authorize(device.device_type, request.resource, request.operation, provisional=True)
    if request.operation.upper() not in permitted_actions or not policy_allows:
        return _deny("POLICY_DENIED", "Operation is not permitted under provisional access")

    return DecisionResponse(
        success=True,
        code="ACCESS_ALLOWED",
        message="Provisional access granted",
        decision="ALLOW",
        details={"jti": payload["jti"], "device_type": device.device_type, "resource": request.resource},
    )


def process_permanent_access(request: PermanentAccessRequest) -> DecisionResponse:
    """Joint integration: Member 1 verifies proof; Member 2 authorizes request."""
    return DecisionResponse(
        success=False,
        code="NOT_IMPLEMENTED",
        message="Permanent verification and authorization are not integrated yet",
        decision="DENY",
    )
