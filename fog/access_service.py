"""MEMBER 2 leads request validation; Member 1 supplies permanent proof verification."""

import base64
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from fog.authorization import authorize
from fog.merkle import verify_inclusion_proof
from fog.models import Device, Epoch, RevokedDevice, UsedNonce
from fog.registration import create_device_leaf, public_key_thumbprint
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
    """Canonical signed resource request, per docs/CONTRACTS.md.
    For permanent access (no token), token_jti is the empty string."""
    return f"{did}|{resource}|{operation}|{body_hash}|{nonce}|{timestamp}|{token_jti}".encode("utf-8")


def _deny(code: str, message: str) -> DecisionResponse:
    return DecisionResponse(success=False, code=code, message=message, decision="DENY")


def _check_fresh_nonce(db: Session, did: str, nonce: str) -> bool:
    """Records (did, nonce) if unseen; returns False if it was already used."""
    try:
        db.add(UsedNonce(did=did, nonce=nonce))
        db.commit()
        return True
    except IntegrityError:
        db.rollback()
        return False


def _verify_request_signature(public_key_pem: str, message: bytes, signature_b64: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


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
    if not _check_fresh_nonce(db, request.did, request.nonce):
        return _deny("NONCE_REUSED", "This nonce has already been used for this device")

    # Request proof-of-possession: a stolen token alone is not enough. The
    # request itself must be signed, fresh, by the device's private key.
    message = _canonical_message(
        request.did, request.resource, request.operation, request.body_hash,
        request.nonce, request.timestamp, payload["jti"],
    )
    if not _verify_request_signature(device.public_key, message, request.signature):
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


def process_permanent_access(request: PermanentAccessRequest, db: Session) -> DecisionResponse:
    """Phase 3 permanent-access pipeline, for a device already included in a
    finalized epoch tree.

    Order of checks: recompute leaf -> obtain trusted epoch root -> verify
    Merkle inclusion proof (identity) -> device revocation -> timestamp
    freshness -> fresh-nonce enforcement -> request-signature verification ->
    role-based / resource-operation authorization (RBAC).
    """
    leaf = create_device_leaf(request.did, request.public_key)
    if leaf.hex() != request.proof.leaf:
        return _deny("INCLUSION_PROOF_INVALID", "Submitted leaf does not match H(DID || public key)")

    epoch = db.get(Epoch, request.epoch_id)
    if epoch is None:
        return _deny("EPOCH_NOT_FOUND", f"No trusted root is anchored for epoch {request.epoch_id}")

    trusted_root = bytes.fromhex(epoch.merkle_root)
    proof_steps = [{"hash": s.hash, "position": s.position} for s in request.proof.siblings]
    if not verify_inclusion_proof(leaf, proof_steps, trusted_root):
        return _deny(
            "INCLUSION_PROOF_INVALID",
            "Reconstructed Merkle root does not match the trusted root for this epoch",
        )

    if db.get(RevokedDevice, request.did) is not None:
        return _deny("DEVICE_REVOKED", "Device is revoked and no longer authorized")

    now = int(time.time())
    if abs(now - request.timestamp) > NONCE_FRESHNESS_SECONDS:
        return _deny("STALE_TIMESTAMP", "Request timestamp is outside the freshness window")

    if not _check_fresh_nonce(db, request.did, request.nonce):
        return _deny("NONCE_REUSED", "This nonce has already been used for this device")

    # Permanent requests carry no token, so the canonical string's final field is empty.
    message = _canonical_message(
        request.did, request.resource, request.operation, request.body_hash,
        request.nonce, request.timestamp, "",
    )
    if not _verify_request_signature(request.public_key, message, request.signature):
        return _deny("REQUEST_SIGNATURE_INVALID", "Request signature does not match the submitted public key")

    # RBAC / resource-operation check. Device type (the framework's "role" for
    # policy purposes) is resolved from the local device record created during
    # registration or provisional-token issuance; a device that reached a
    # finalized epoch without ever populating that record is a configuration
    # gap upstream, not a valid identity to authorize here.
    device = db.query(Device).filter_by(did=request.did).one_or_none()
    if device is None:
        return _deny("DEVICE_NOT_FOUND", "No local device record to resolve a role/device type from")

    policy_allows = authorize(device.device_type, request.resource, request.operation, provisional=False)
    if not policy_allows:
        return _deny("POLICY_DENIED", "Operation is not permitted for this device type under permanent access")

    return DecisionResponse(
        success=True,
        code="ACCESS_ALLOWED",
        message="Permanent access granted",
        decision="ALLOW",
        details={
            "epoch_id": request.epoch_id,
            "device_type": device.device_type,
            "resource": request.resource,
        },
    )
